/* Finite LLVM C-ABI observer. Native calls execute only in the admitted hosted job. */
#define _DARWIN_C_SOURCE 1
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#ifdef __APPLE__
#include <mach/mach.h>
#endif

#define CAPACITY 256
typedef void *Ref;
typedef struct { Ref pointer; uint64_t size; unsigned state; } Entry;
static Entry entries[CAPACITY];
static unsigned used;
static uint64_t counters[32];
static void *image;
static char error_text[512];
static char parse_error_text[1024];
static char image_path[4096];
static Ref module, context;
static Ref (*create_copy)(const char *, size_t, const char *);
static int (*create_file)(const char *, Ref *, char **);
static const char *(*buffer_start)(Ref);
static size_t (*buffer_size)(Ref);
static void (*dispose_buffer)(Ref);
static Ref (*context_create)(void);
static void (*context_dispose)(Ref);
static int (*parse_bitcode)(Ref, Ref, Ref *);
static int (*parse_ir)(Ref, Ref, Ref *, char **);
static Ref (*write_bitcode)(Ref);
static void (*module_dispose)(Ref);
static int (*verify_module)(Ref, int, char **);
static char *(*print_module)(Ref);
static void (*dispose_message)(char *);
static void (*get_version)(unsigned *, unsigned *, unsigned *);
static void (*set_diagnostic_handler)(Ref, void (*)(Ref, void *), void *);
static char *(*diagnostic_description)(Ref);

static int fail(const char *text) {
  counters[9]++;
  snprintf(error_text, sizeof(error_text), "%s", text ? text : "native error text unavailable");
  return 0;
}
static int symbol(const char *name, void *target, size_t size) {
  void *address = dlsym(image, name);
  if (!address || size != sizeof(address)) return fail(name);
  Dl_info info;
  if (!dladdr(address, &info) || !info.dli_fname || strlen(info.dli_fname) >= sizeof(image_path))
    return fail("resolved native symbol image identity unavailable");
  if (image_path[0] && strcmp(image_path, info.dli_fname) != 0)
    return fail("all reviewed LLVM symbols must resolve to one image");
  if (!image_path[0]) strcpy(image_path, info.dli_fname);
  memcpy(target, &address, size);
  return 1;
}
#define LOAD(field, name) if (!symbol(name, &field, sizeof(field))) return 0
static void diagnostic(Ref info, void *opaque) {
  (void)opaque; counters[15]++;
  char *message = diagnostic_description(info);
  snprintf(parse_error_text, sizeof(parse_error_text), "%s", message ? message : "diagnostic text unavailable");
  if (message) dispose_message(message);
}
int atlas_initialize(const char *path) {
  if (image) return fail("single initialization required");
  image = dlopen(path, RTLD_NOW | RTLD_LOCAL);
  if (!image) return fail(dlerror());
  LOAD(create_copy, "LLVMCreateMemoryBufferWithMemoryRangeCopy");
  LOAD(create_file, "LLVMCreateMemoryBufferWithContentsOfFile");
  LOAD(buffer_start, "LLVMGetBufferStart");
  LOAD(buffer_size, "LLVMGetBufferSize");
  LOAD(dispose_buffer, "LLVMDisposeMemoryBuffer");
  LOAD(context_create, "LLVMContextCreate");
  LOAD(context_dispose, "LLVMContextDispose");
  LOAD(parse_bitcode, "LLVMParseBitcodeInContext2");
  LOAD(parse_ir, "LLVMParseIRInContext");
  LOAD(write_bitcode, "LLVMWriteBitcodeToMemoryBuffer");
  LOAD(module_dispose, "LLVMDisposeModule");
  LOAD(verify_module, "LLVMVerifyModule");
  LOAD(print_module, "LLVMPrintModuleToString");
  LOAD(dispose_message, "LLVMDisposeMessage");
  LOAD(get_version, "LLVMGetVersion");
  LOAD(set_diagnostic_handler, "LLVMContextSetDiagnosticHandler");
  LOAD(diagnostic_description, "LLVMGetDiagInfoDescription");
  unsigned major = 0, minor = 0, patch = 0;
  get_version(&major, &minor, &patch);
  if (major != 21 || minor != 1 || patch != 8) return fail("LLVM21.1.8 required");
  Dl_info info;
  if (!dladdr(dlsym(image, "LLVMDisposeMemoryBuffer"), &info) || !info.dli_fname)
    return fail("loaded LLVM image identity unavailable");
  if (strlen(info.dli_fname) >= sizeof(image_path)) return fail("loaded image path bound");
  strcpy(image_path, info.dli_fname);
  return 1;
}
const char *atlas_error(void) { return error_text; }
const char *atlas_image(void) { return image_path; }
const char *atlas_parse_error(void) { return parse_error_text; }
static Entry *find_live(Ref pointer) {
  for (unsigned i = used; i > 0; --i)
    if (entries[i-1].pointer == pointer && entries[i-1].state == 1) return &entries[i-1];
  return NULL;
}
static Ref own(Ref pointer) {
  if (!pointer) { fail("native allocation returned null"); return NULL; }
  if (used >= CAPACITY || find_live(pointer)) {
    /* Capacity is checked before insertion; a new native result still returns. */
    dispose_buffer(pointer); fail("finite distinct live registry required"); return NULL;
  }
  uint64_t size = buffer_size(pointer);
  entries[used++] = (Entry){pointer, size, 1};
  counters[0]++; counters[1] += size; counters[2] += size;
  if (counters[2] > counters[3]) counters[3] = counters[2];
  return pointer;
}
Ref atlas_copy(uint64_t size) {
  if (size == 0 || size > 1048576) { fail("copy size bound"); return NULL; }
  char *input = malloc((size_t)size);
  if (!input) { fail("source allocation failed"); return NULL; }
  memset(input, 81, (size_t)size);
  Ref result = own(create_copy(input, (size_t)size, "atlas-known-copy"));
  free(input);
  return result;
}
int atlas_create_file(const char *path, Ref *result, char **message) {
  *result = NULL; *message = NULL;
  int status = create_file(path, result, message);
  if (status == 0) *result = own(*result);
  else counters[14]++;
  return status;
}
const char *atlas_buffer_start(Ref pointer) {
  if (!find_live(pointer)) { fail("live buffer required for slice"); return NULL; }
  return buffer_start(pointer);
}
size_t atlas_buffer_size(Ref pointer) {
  if (!find_live(pointer)) { fail("live buffer required for size"); return 0; }
  return buffer_size(pointer);
}
void atlas_dispose(Ref pointer) {
  Entry *entry = find_live(pointer);
  counters[4]++; /* Wrapper's attempted native disposer call. */
  if (!entry) { counters[6]++; return; } /* Intercept before a real duplicate delete. */
  counters[5]++; /* Real LLVMDisposeMemoryBuffer entered. */
  dispose_buffer(pointer);
  counters[7]++; /* Real LLVMDisposeMemoryBuffer returned. */
  entry->state = 2;
  counters[2] -= entry->size;
  counters[8] += entry->size;
}
static Ref new_context(void) {
  Ref result = context_create();
  if (result) { counters[17]++; set_diagnostic_handler(result, diagnostic, NULL); }
  else fail("native context allocation failed");
  return result;
}
void atlas_close_module(void) {
  if (module) { module_dispose(module); module = NULL; counters[19]--; }
  if (context) { context_dispose(context); context = NULL; counters[18]++; }
}
Ref atlas_ir_copy(int valid) {
  const char *text = valid ? "define i32 @answer() { ret i32 42 }\n" : "this is invalid LLVM IR\n";
  return own(create_copy(text, strlen(text), "atlas-ir"));
}
int atlas_consume_ir(Ref pointer) {
  Entry *entry = find_live(pointer);
  if (!entry) return fail("owned input required before consuming IR");
  atlas_close_module(); context = new_context();
  if (!context) return 0;
  /* Retire caller ownership before the native consuming call, for either result. */
  entry->state = 3; counters[2] -= entry->size; counters[10] += entry->size;
  counters[11]++;
  char *message = NULL;
  parse_error_text[0] = 0;
  int status = parse_ir(context, pointer, &module, &message);
  counters[12]++;
  if (module) counters[19]++;
  if (message) {
    snprintf(parse_error_text, sizeof(parse_error_text), "%s", message);
    dispose_message(message);
  }
  return status == 0 ? 1 : 0;
}
int atlas_borrow_bitcode(Ref pointer) {
  if (!find_live(pointer)) return fail("owned input required for borrowed bitcode");
  atlas_close_module(); context = new_context();
  if (!context) return 0;
  counters[13]++;
  parse_error_text[0] = 0;
  int status = parse_bitcode(context, pointer, &module);
  if (module) counters[19]++;
  return status == 0 ? 1 : 0;
}
int atlas_verify_answer(void) {
  if (!module) return fail("independent native module required");
  char *message = NULL;
  int status = verify_module(module, 2, &message); /* LLVMReturnStatusAction */
  if (message) dispose_message(message);
  char *text = print_module(module);
  int useful = status == 0 && text && strstr(text, "ret i32 42") != NULL;
  if (text) dispose_message(text);
  if (useful) counters[16]++;
  else fail("verified answer42 module required");
  return useful;
}
Ref atlas_bitcode_copy(void) {
  Ref ir = atlas_ir_copy(1);
  if (!ir || !atlas_consume_ir(ir) || !atlas_verify_answer()) return NULL;
  Ref result = own(write_bitcode(module));
  atlas_close_module();
  return result;
}
void atlas_message_dispose(char *message) { dispose_message(message); }
void atlas_cleanup(void) {
  atlas_close_module();
  for (unsigned i = 0; i < used; ++i)
    if (entries[i].state == 1) atlas_dispose(entries[i].pointer);
}
uint64_t atlas_counter(unsigned key) {
  if (key < 20) return counters[key];
  if (key == 23) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
  }
  if (key == 21) {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0) return 0;
#ifdef __APPLE__
    return (uint64_t)usage.ru_maxrss; /* Darwin bytes; distinct from current RSS. */
#else
    return (uint64_t)usage.ru_maxrss * 1024ULL;
#endif
  }
  if (key == 24 || key == 25) {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0) return 0;
    struct timeval value = key == 24 ? usage.ru_utime : usage.ru_stime;
    return (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_usec * 1000ULL;
  }
#ifdef __APPLE__
  if (key == 20) {
    mach_task_basic_info_data_t info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &count) == KERN_SUCCESS)
      return (uint64_t)info.resident_size;
  }
  if (key == 22) {
    task_vm_info_data_t info;
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count) == KERN_SUCCESS)
      return (uint64_t)info.phys_footprint;
  }
#endif
  return 0;
}
