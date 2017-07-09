#include <mruby.h>
#include <mruby/class.h>
#include <mruby/hash.h>
#include <mruby/string.h>
#include <mruby/value.h>
#include <mruby/data.h>
#include <mruby/variable.h>
#include <mruby/error.h>
#include <stdlib.h>
#include <lzma.h>
#include "extdefs.h"
#include "mrbx_kwargs.h"


#ifndef AUX_LZMA_PARTIAL_SIZE
#   if defined(MRB_INT16)
#       define AUX_LZMA_PARTIAL_SIZE ((uint32_t)4 << 10)
#   else
#       define AUX_LZMA_PARTIAL_SIZE ((uint32_t)1 << 20)
#   endif
#endif

#ifndef AUX_DOUBLE_EXPAND_MAX
#   if defined(MRB_INT16)
#       define AUX_DOUBLE_EXPAND_MAX ((uint32_t)4 << 10)
#   else
#       define AUX_DOUBLE_EXPAND_MAX ((uint32_t)4 << 20)
#   endif
#endif

#define NIL_OR_DEFAULT(primary, secondary) (NIL_P(primary) ? (secondary) : (primary))
#define CLAMP(n, min, max) (n < min ? min : (n > max ? max : n))
#define CLAMP_MAX(n, max) (n > max ? max : n)

#define id_initialize   mrb_intern_lit(mrb, "initialize")
#define id_none     mrb_intern_lit(mrb, "none")
#define id_crc32    mrb_intern_lit(mrb, "crc32")
#define id_crc64    mrb_intern_lit(mrb, "crc64")
#define id_sha256   mrb_intern_lit(mrb, "sha256")
#define id_x86      mrb_intern_lit(mrb, "x86")
#define id_powerpc  mrb_intern_lit(mrb, "powerpc")
#define id_ia64     mrb_intern_lit(mrb, "ia64")
#define id_arm      mrb_intern_lit(mrb, "arm")
#define id_armthumb mrb_intern_lit(mrb, "armthumb")
#define id_sparc    mrb_intern_lit(mrb, "sparc")

#define DECLARE_IV_ACCESSOR(varname, setter, getter) \
    static void \
    setter(MRB, VALUE o, VALUE v) \
    { \
        mrb_iv_set(mrb, o, mrb_intern_lit(mrb, "mruby-lzma." varname), v); \
    } \
 \
    static VALUE \
    getter(MRB, VALUE o) \
    { \
        return mrb_iv_get(mrb, o, mrb_intern_lit(mrb, "mruby-lzma." varname)); \
    } \

DECLARE_IV_ACCESSOR("inport", aux_set_inport, aux_get_inport)
DECLARE_IV_ACCESSOR("outport", aux_set_outport, aux_get_outport)
DECLARE_IV_ACCESSOR("filters", aux_set_filters, aux_get_filters)
DECLARE_IV_ACCESSOR("srcbuf", aux_set_srcbuf, aux_get_srcbuf)
DECLARE_IV_ACCESSOR("destbuf", aux_set_destbuf, aux_get_destbuf)

static inline VALUE
aux_conv_hexdigest(MRB, uint64_t n, int bytesize)
{
    int off = bytesize * 8;
    VALUE str = mrb_str_buf_new(mrb, bytesize * 2);
    char *p = RSTRING_PTR(str);
    for (; off > 0; off -= 4, p ++) {
        uint8_t ch = (n >> (off - 4)) & 0x0f;
        if (ch < 10) {
            *p = '0' + ch;
        } else {
            *p = 'a' - 10 + ch;
        }
    }
    RSTR_SET_LEN(mrb_str_ptr(str), bytesize * 2);
    return str;
}

static inline VALUE
aux_conv_uint64(MRB, uint64_t n, int bytesize)
{
#ifndef MRB_INT64
    int64_t m = (int64_t)n << (64 - bytesize * 8) >> (64 - bytesize * 8);
    if (m > MRB_INT_MAX || m < MRB_INT_MIN) {
        return aux_conv_hexdigest(mrb, m, bytesize);
    }
#endif

    return mrb_fixnum_value(n);
}

static inline uint64_t
aux_to_uint64(MRB, VALUE n)
{
    if (mrb_float_p(n)) {
        return mrb_float(n);
    } else if (mrb_string_p(n)) {
        return strtoull(RSTRING_PTR(n), NULL, 16);
    } else {
        return mrb_int(mrb, n);
    }
}

static void *
LZMA_API_CALL aux_lzma_calloc(void *opaque, size_t nmemb, size_t size)
{
    size *= nmemb;
    if (size < nmemb) {
        return NULL;
    } else {
        return mrb_malloc_simple((mrb_state *)opaque, size);
    }
}

static void
LZMA_API_CALL aux_lzma_free(void *opaque, void *ptr)
{
    mrb_free((mrb_state *)opaque, ptr);
}

static inline lzma_allocator
aux_lzma_allocator(MRB)
{
    lzma_allocator allocator = {
        .alloc = aux_lzma_calloc,
        .free = aux_lzma_free,
        .opaque = (void *)mrb,
    };

    return allocator;
}

static lzma_check
aux_to_check(MRB, VALUE check)
{
    if (NIL_P(check)) {
        return LZMA_CHECK_CRC64;
    } else {
        mrb_sym acheck = mrb_symbol(check);
        if (acheck == id_crc64) {
            return LZMA_CHECK_CRC64;
        } else if (acheck == id_crc32) {
            return LZMA_CHECK_CRC32;
        } else if (acheck == id_sha256) {
            return LZMA_CHECK_SHA256;
        } else if (acheck == id_none) {
            return LZMA_CHECK_NONE;
        }
    }

    mrb_raise(mrb, E_ARGUMENT_ERROR,
              "wrong check value (expect :none, :crc32, :crc64, :sha256 or nil)");
}

static const char *
aux_error_string(lzma_ret code)
{
    switch (code) {
    case LZMA_OK:                return "LZMA_OK - Operation completed successfully";
    case LZMA_STREAM_END:        return "LZMA_STREAM_END - End of stream was reached";
    case LZMA_NO_CHECK:          return "LZMA_NO_CHECK - Input stream has no integrity check";
    case LZMA_UNSUPPORTED_CHECK: return "LZMA_UNSUPPORTED_CHECK - Cannot calculate the integrity check";
    case LZMA_GET_CHECK:         return "LZMA_GET_CHECK - Integrity check type is now available";
    case LZMA_MEM_ERROR:         return "LZMA_MEM_ERROR - Cannot allocate memory";
    case LZMA_MEMLIMIT_ERROR:    return "LZMA_MEMLIMIT_ERROR - Memory usage limit was reached";
    case LZMA_FORMAT_ERROR:      return "LZMA_FORMAT_ERROR - File format not recognized";
    case LZMA_OPTIONS_ERROR:     return "LZMA_OPTIONS_ERROR - Invalid or unsupported options";
    case LZMA_DATA_ERROR:        return "LZMA_DATA_ERROR - Data is corrupt";
    case LZMA_BUF_ERROR:         return "LZMA_BUF_ERROR - No progress is possible";
    case LZMA_PROG_ERROR:        return "LZMA_PROG_ERROR - Programming error";
#ifdef LZMA_SEEK_NEEDED
    case LZMA_SEEK_NEEDED:       return "LZMA_SEEK_NEEDED - Request to change the input file position";
#endif
    default:                     return "UNKNOWN ERROR";
    }
}

static void
aux_check_error(MRB, lzma_ret code, const char *mesg)
{
    if (code == LZMA_OK) { return; }

    mrb_gc_arena_restore(mrb, 0);
    if (mesg) {
        mrb_raisef(mrb, E_RUNTIME_ERROR,
                   "%S failed - %S (code:%S)",
                   mrb_str_new_cstr(mrb, mesg),
                   mrb_str_new_cstr(mrb, aux_error_string(code)),
                   mrb_fixnum_value(code));
    } else {
        mrb_raisef(mrb, E_RUNTIME_ERROR,
                   "lzma failed - %S (code:%S)",
                   mrb_str_new_cstr(mrb, aux_error_string(code)),
                   mrb_fixnum_value(code));
    }
}

static void
aux_check_preset(MRB, lzma_bool status)
{
    if (!status) { return; }

    mrb_raise(mrb, E_RUNTIME_ERROR, "wrong preset");
}

static uint32_t
aux_to_u32(MRB, VALUE size)
{
    if (NIL_P(size)) {
        return 0;
    }

    if (mrb_float_p(size)) {
        mrb_float n = mrb_float(size);
        return CLAMP(n, 0, UINT32_MAX);
    } else {
        mrb_int n = mrb_int(mrb, size);
        return CLAMP(n, 0, UINT32_MAX);
    }
}

static uint64_t
aux_to_u64(MRB, VALUE size)
{
    if (NIL_P(size)) {
        return 0;
    }

    if (mrb_float_p(size)) {
        mrb_float n = mrb_float(size);
        return CLAMP(n, 0, UINT64_MAX);
    } else {
        mrb_int n = mrb_int(mrb, size);
        return CLAMP(n, 0, UINT64_MAX);
    }
}

static VALUE
aux_str_resize(MRB, VALUE str, size_t size)
{
    if (size > MRB_INT_MAX) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "more than MRB_INT_MAX when request memory allocation");
    }

    if (NIL_P(str)) {
        str = mrb_str_buf_new(mrb, size);
    } else {
        mrb_check_type(mrb, str, MRB_TT_STRING);
    }

    mrb_str_resize(mrb, str, size);

    return str;
}

static VALUE
aux_str_reserve(MRB, VALUE str, size_t size)
{
    if (size > MRB_INT_MAX) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "more than MRB_INT_MAX when request memory allocation");
    }

    if (NIL_P(str) || MRB_FROZEN_P(RSTRING(str))) {
        str = mrb_str_buf_new(mrb, size);
    } else {
        mrb_check_type(mrb, str, MRB_TT_STRING);
    }

    mrb_str_resize(mrb, str, size);

    return str;
}

static inline mrb_bool
aux_is_module(VALUE obj)
{
    enum mrb_vtype type = mrb_type(obj);
    return (type == MRB_TT_CLASS ||
            type == MRB_TT_MODULE ||
            type == MRB_TT_ICLASS ||
            type == MRB_TT_SCLASS);
}

static VALUE
dig_const_without_raise(MRB, struct RClass *root, const char *names[])
{
    if (!root) { root = mrb->object_class; }

    VALUE obj = mrb_obj_value(root);
    for (; *names != NULL; names ++) {
        if (!aux_is_module(obj)) {
            return mrb_undef_value();
        }

        mrb_sym id = mrb_intern_cstr(mrb, *names);
        if (!mrb_const_defined(mrb, obj, id)) {
            return mrb_undef_value();
        }
        obj = mrb_const_get(mrb, obj, id);
    }

    return obj;
}

#define DIG_CONST(mrb, root, ...)                                   \
    ({                                                              \
        const char *names___[] = { __VA_ARGS__, NULL };             \
        VALUE obj = dig_const_without_raise(mrb, root, names___);   \
        if (mrb_undef_p(obj)) {                                     \
            mrb_raise(mrb, E_RUNTIME_ERROR, "not defined const");   \
        }                                                           \
        obj;                                                        \
    })                                                              \

#define DIG_MODULE(mrb, root, ...)                                  \
    ({                                                              \
        VALUE obj = DIG_CONST(mrb, root, __VA_ARGS__);              \
        if (!aux_is_module(obj)) {                                  \
            mrb_raise(mrb, E_RUNTIME_ERROR, "not a class/module");  \
        }                                                           \
        obj;                                                        \
    })                                                              \

#define DIG_MODULE_PTR(mrb, root, ...)                              \
        mrb_class_ptr(DIG_MODULE(mrb, root, __VA_ARGS__));          \

static inline VALUE
aux_str_set_len(MRB, VALUE str, size_t size)
{
    if (size > MRB_INT_MAX) {
        mrb_raise(mrb, E_RUNTIME_ERROR,
                  "request set to string length is too huge (more than MRB_INT_MAX)");
    }
    RSTR_SET_LEN(RSTRING(str), size);
    return str;
}

static VALUE
aux_lzma_code_expand_body(MRB, VALUE args)
{
    struct args_t {
        lzma_stream *stream;
        VALUE dest;
    } *p = (struct args_t *)mrb_cptr(args);

    for (;;) {
        lzma_ret s = lzma_code(p->stream, LZMA_FINISH);
        if (s == LZMA_STREAM_END) {
            break;
        }
        aux_check_error(mrb, s, "lzma_code");

        size_t size = RSTRING_CAPA(p->dest);
        if (size > AUX_DOUBLE_EXPAND_MAX) {
            size += AUX_DOUBLE_EXPAND_MAX;
        } else {
            size <<= 1;
        }
        aux_str_resize(mrb, p->dest, size);
        p->stream->next_out = (uint8_t *)RSTRING_PTR(p->dest) + p->stream->total_out;
        p->stream->avail_out = RSTRING_CAPA(p->dest) - p->stream->total_out;
    }

    aux_str_set_len(mrb, p->dest, p->stream->total_out);

    return Qnil;
}

static VALUE
aux_lzma_code_expand_ensure(MRB, VALUE args)
{
    struct args_t {
        lzma_stream *stream;
        VALUE dest;
    } *p = (struct args_t *)mrb_cptr(args);

    lzma_end(p->stream);
    return Qnil;
}

static VALUE
aux_lzma_code_expand(MRB, lzma_stream *stream, VALUE dest)
{
    struct {
        lzma_stream *stream;
        VALUE dest;
    } args = { stream, dest };

    VALUE argsp = mrb_cptr_value(mrb, &args);

    mrb_ensure(mrb,
               aux_lzma_code_expand_body, argsp,
               aux_lzma_code_expand_ensure, argsp);
    return dest;
}

static mrb_sym
aux_get_called_mid(MRB)
{
    return mrb->c->ci->mid;
}

static VALUE
aux_notimp_method(MRB, VALUE self)
{
    mrb_raisef(mrb, E_NOTIMP_ERROR,
               "``%S'' is not implemented",
               mrb_symbol_value(aux_get_called_mid(mrb)));
}

#define ALLOCATE_OBJECT(mrb, self, type, datatype, ptr) \
    ({ \
        struct RData *rd_; \
        Data_Make_Struct(mrb, mrb_class_ptr(self), type, datatype, ptr, rd_); \
        mrb_obj_value(rd_); \
    }) \

#define THROUGH_TO_INITIALIZE(mrb, obj)                                     \
    ({                                                                      \
        mrb_int argc;                                                       \
        mrb_value *argv;                                                    \
        mrb_get_args(mrb, "*", &argv, &argc);                               \
        mrb_funcall_argv(mrb, obj, id_initialize, argc, argv);              \
    })                                                                      \

#define NEW_OBJECT(mrb, self, datatype, type, birthcode)                    \
    ({                                                                      \
        type *p;                                                            \
        VALUE obj = ALLOCATE_OBJECT(mrb, self, type, datatype, p);          \
                                                                            \
        do { birthcode; } while (0);                                        \
                                                                            \
        THROUGH_TO_INITIALIZE(mrb, obj);                                    \
                                                                            \
        obj;                                                                \
    })                                                                      \

static void *
getref(MRB, VALUE self, const mrb_data_type *datatype)
{
    void *p;
    Data_Get_Struct(mrb, self, datatype, p);
    return p;
}

static void setup_filter(MRB, lzma_filter *filterp, VALUE filter);

static mrb_int
aux_args_to_filter(MRB, mrb_int argc, VALUE argv[], VALUE *afilters, lzma_filter filters[LZMA_FILTERS_MAX + 1])
{
    struct RClass *cFilter = DIG_MODULE_PTR(mrb, NULL, "LZMA", "Filter");
    int filtstart;
    for (filtstart = argc - 1; filtstart > 0; filtstart --) {
        if (!mrb_obj_is_kind_of(mrb, argv[filtstart], cFilter)) {
            break;
        }
    }
    filtstart ++;

    if (argc - filtstart > LZMA_FILTERS_MAX) {
        mrb_raisef(mrb, E_ARGUMENT_ERROR,
                   "wrong number of filters (given %S, expect 0..%S)",
                   mrb_fixnum_value(argc - filtstart),
                   mrb_fixnum_value(LZMA_FILTERS_MAX));
    }

    if (argc - filtstart > 0) {
        if (afilters) {
            *afilters = mrb_ary_new_from_values(mrb, argc - filtstart, &argv[filtstart]);
        }
        for (int i = 0; (filtstart + i) < argc; i ++) {
            setup_filter(mrb, &filters[i], argv[filtstart + i]);
        }
        filters[argc - filtstart].id = LZMA_VLI_UNKNOWN;
        argc = filtstart;
    } else {
        if (afilters) {
            *afilters = Qnil;
        }
    }

    return argc;
}

static mrb_int
aux_decoder_options(MRB, mrb_int argc, VALUE *argv, uint64_t *memlimit, uint32_t *flags)
{
    if (argc > 0 && mrb_hash_p(argv[argc - 1])) {
        argc --;
        VALUE values[6];
        MRBX_SCANHASH(mrb, argv[argc], Qnil,
                MRBX_SCANHASH_ARGS("memlimit", &values[0], Qnil),
                MRBX_SCANHASH_ARGS("tell_no_check", &values[1], Qnil),
                MRBX_SCANHASH_ARGS("tell_unsupported_check", &values[2], Qnil),
                MRBX_SCANHASH_ARGS("tell_any_check", &values[3], Qnil),
                MRBX_SCANHASH_ARGS("ignore_check", &values[4], Qnil),
                MRBX_SCANHASH_ARGS("concatenated", &values[5], Qnil));
        *memlimit = aux_to_u64(mrb, values[0]);
        *flags = (NIL_P(values[1]) || !mrb_bool(values[1]) ? 0 : LZMA_TELL_NO_CHECK) |
                 (NIL_P(values[2]) || !mrb_bool(values[2]) ? 0 : LZMA_TELL_UNSUPPORTED_CHECK) |
                 (NIL_P(values[3]) || !mrb_bool(values[3]) ? 0 : LZMA_TELL_ANY_CHECK) |
                 (NIL_P(values[4]) || !mrb_bool(values[4]) ? 0 : LZMA_IGNORE_CHECK) |
                 (NIL_P(values[5]) || !mrb_bool(values[5]) ? 0 : LZMA_CONCATENATED);
    } else {
        *memlimit = 0;
        *flags = 0;
    }

    return argc;
}

static VALUE
aux_read(MRB, VALUE inport, size_t size, VALUE buf, size_t *offset)
{
    if (mrb_string_p(inport)) {
        size_t len = RSTRING_LEN(inport);
        if (*offset >= len) {
            return Qnil;
        } else {
            size = CLAMP_MAX(size, len - *offset);
            buf = aux_str_reserve(mrb, buf, size);
            memcpy(RSTRING_PTR(buf), RSTRING_PTR(inport) + *offset, size);
            RSTR_SET_LEN(RSTRING(buf), size);
            *offset = size;
            return buf;
        }
    } else {
        buf = aux_str_reserve(mrb, buf, size);
        return FUNCALLC(mrb, inport, "read", mrb_fixnum_value(size), buf);
    }
}

#define TUPLE(mrb, ...) \
    ({ \
        VALUE ary__[] = { __VA_ARGS__ }; \
        mrb_ary_new_from_values(mrb, ELEMENTOF(ary__), ary__); \
    }) \

/*
 * class LZMA::Filter
 * class LZMA::LZMA1
 * class LZMA::LZMA2
 * class LZMA::Delta
 * class LZMA::BCJ
 */

struct filter_lzmaX
{
    lzma_options_lzma options;
    VALUE predict;
};

static void
filter_lzmaX_free(MRB, struct filter_lzmaX *p)
{
    mrb_free(mrb, p);
}

static const mrb_data_type filter_lzma1_type = {
    .struct_name = "mruby-lzma.filter.lzma1",
    .dfree = (void (*)(mrb_state *, void *))filter_lzmaX_free,
};

static const mrb_data_type filter_lzma2_type = {
    .struct_name = "mruby-lzma.filter.lzma2",
    .dfree = (void (*)(mrb_state *, void *))filter_lzmaX_free,
};

static struct filter_lzmaX *
getfilter_lzmaX(MRB, VALUE self, const mrb_data_type **type)
{
    struct filter_lzmaX *p = (struct filter_lzmaX *)mrb_data_check_get_ptr(mrb, self, &filter_lzma1_type);
    if (p) {
        if (type) { *type = &filter_lzma1_type; }
        return p;
    }

    Data_Get_Struct(mrb, self, &filter_lzma2_type, p);

    if (type) { *type = &filter_lzma2_type; }

    return p;
}

/*
 * call-seq:
 *  new(preset = LZMA::DEFAULT_PRESET, opts = {})
 */
static VALUE
filter_lzma1_s_new(MRB, VALUE self)
{
    return NEW_OBJECT(mrb, self, &filter_lzma1_type, struct filter_lzmaX, {});
}

/*
 * call-seq:
 *  new(preset = LZMA::DEFAULT_PRESET, opts = {})
 */
static VALUE
filter_lzma2_s_new(MRB, VALUE self)
{
    return NEW_OBJECT(mrb, self, &filter_lzma2_type, struct filter_lzmaX, {});
}

static VALUE
filter_lzmaX_initialize(MRB, VALUE self)
{
    struct filter_lzmaX *p = getfilter_lzmaX(mrb, self, NULL);

    mrb_int preset = LZMA_PRESET_DEFAULT;
    mrb_get_args(mrb, "|i", &preset);

    aux_check_preset(mrb, lzma_lzma_preset(&p->options, preset));

    return self;
}


struct filter_delta
{
    lzma_options_delta options;
};

static void
filter_delta_free(MRB, struct filter_delta *p)
{
    mrb_free(mrb, p);
}

static const mrb_data_type filter_delta_type = {
    .struct_name = "mruby-lzma.filter.delta",
    .dfree = (void (*)(mrb_state *, void *))filter_delta_free,
};

static struct filter_delta *
getfilter_delta(MRB, VALUE self)
{
    struct filter_delta *p;
    Data_Get_Struct(mrb, self, &filter_delta_type, p);
    return p;
}

/*
 * call-seq:
 *  new(distance = 1)
 */
static VALUE
filter_delta_s_new(MRB, VALUE self)
{
    return NEW_OBJECT(mrb, self, &filter_delta_type, struct filter_delta, {});
}

static VALUE
filter_delta_initialize(MRB, VALUE self)
{
    struct filter_delta *p = getfilter_delta(mrb, self);
    mrb_int distance = 1;
    mrb_get_args(mrb, "|i", &distance);
    p->options.type = LZMA_DELTA_TYPE_BYTE;
    p->options.dist = distance;
    return self;
}

struct filter_bcj
{
    lzma_options_bcj options;
    uint32_t cputype;
};

static void
filter_bcj_free(MRB, struct filter_bcj *p)
{
    mrb_free(mrb, p);
}

static const mrb_data_type filter_bcj_type = {
    .struct_name = "mruby-lzma.filter.bcj",
    .dfree = (void (*)(mrb_state *, void *))filter_bcj_free,
};

static struct filter_bcj *
getfilter_bcj(MRB, VALUE self)
{
    struct filter_bcj *p;
    Data_Get_Struct(mrb, self, &filter_bcj_type, p);
    return p;
}

/*
 * call-seq:
 *  new(cputype, offset = 0)
 *
 * [cputype]
 *  Give CPU architecture for :x86, :powerpc, :ia64, :arm, :armthumb or :sparc
 */
static VALUE
filter_bcj_s_new(MRB, VALUE self)
{
    return NEW_OBJECT(mrb, self, &filter_bcj_type, struct filter_bcj, {});
}

static VALUE
filter_bcj_initialize(MRB, VALUE self)
{
    struct filter_bcj *p = getfilter_bcj(mrb, self);
    mrb_sym cputype;
    mrb_int offset = 0;
    mrb_get_args(mrb, "n|i", &cputype, &offset);

    if (cputype == id_x86) {
        p->cputype = LZMA_FILTER_X86;
    } else if (cputype == id_powerpc) {
        p->cputype = LZMA_FILTER_POWERPC;
    } else if (cputype == id_ia64) {
        p->cputype = LZMA_FILTER_IA64;
    } else if (cputype == id_arm) {
        p->cputype = LZMA_FILTER_ARM;
    } else if (cputype == id_armthumb) {
        p->cputype = LZMA_FILTER_ARMTHUMB;
    } else if (cputype == id_sparc) {
        p->cputype = LZMA_FILTER_SPARC;
    } else {
        mrb_raise(mrb, E_ARGUMENT_ERROR,
                  "wrong cpu-type (expect :x86, :powerpc, :ia64, :arm, :armthumb or :sparc)");
    }

    if (offset < 0) {
        mrb_raise(mrb, E_ARGUMENT_ERROR,
                  "wrong negative offset");
    } else {
        p->options.start_offset = offset;
    }

    return self;
}

static void
init_filter(MRB, struct RClass *mLZMA)
{
    struct RClass *cFilter = mrb_define_class_under(mrb, mLZMA, "Filter", mrb_cObject);
    MRB_SET_INSTANCE_TT(cFilter, MRB_TT_DATA);
    mrb_define_class_method(mrb, cFilter, "new", aux_notimp_method, MRB_ARGS_ANY());
    mrb_define_method(mrb, cFilter, "initialize", aux_notimp_method, MRB_ARGS_ANY());

    struct RClass *cLZMA1 = mrb_define_class_under(mrb, mLZMA, "LZMA1", cFilter);
    mrb_define_class_method(mrb, cLZMA1, "new", filter_lzma1_s_new, MRB_ARGS_ANY());
    mrb_define_method(mrb, cLZMA1, "initialize", filter_lzmaX_initialize, MRB_ARGS_ANY());

    struct RClass *cLZMA2 = mrb_define_class_under(mrb, mLZMA, "LZMA2", cFilter);
    mrb_define_class_method(mrb, cLZMA2, "new", filter_lzma2_s_new, MRB_ARGS_ANY());
    mrb_define_method(mrb, cLZMA2, "initialize", filter_lzmaX_initialize, MRB_ARGS_ANY());

    struct RClass *cDelta = mrb_define_class_under(mrb, mLZMA, "Delta", cFilter);
    mrb_define_class_method(mrb, cDelta, "new", filter_delta_s_new, MRB_ARGS_ANY());
    mrb_define_method(mrb, cDelta, "initialize", filter_delta_initialize, MRB_ARGS_ANY());

    struct RClass *cBCJ = mrb_define_class_under(mrb, mLZMA, "BCJ", cFilter);
    mrb_define_class_method(mrb, cBCJ, "new", filter_bcj_s_new, MRB_ARGS_ANY());
    mrb_define_method(mrb, cBCJ, "initialize", filter_bcj_initialize, MRB_ARGS_ANY());
}

static void
setup_filter(MRB, lzma_filter *filterp, VALUE filter)
{
    {
        struct filter_lzmaX *p = (struct filter_lzmaX *)mrb_data_check_get_ptr(mrb, filter, &filter_lzma1_type);
        if (p) {
            filterp->id = LZMA_FILTER_LZMA1;
            filterp->options = (void *)&p->options;
            return;
        }
    }

    {
        struct filter_lzmaX *p = (struct filter_lzmaX *)mrb_data_check_get_ptr(mrb, filter, &filter_lzma2_type);
        if (p) {
            filterp->id = LZMA_FILTER_LZMA2;
            filterp->options = (void *)&p->options;
            return;
        }
    }

    {
        struct filter_delta *p = (struct filter_delta *)mrb_data_check_get_ptr(mrb, filter, &filter_delta_type);
        if (p) {
            filterp->id = LZMA_FILTER_DELTA;
            filterp->options = (void *)&p->options;
            return;
        }
    }

    {
        struct filter_bcj *p = (struct filter_bcj *)mrb_data_check_get_ptr(mrb, filter, &filter_bcj_type);
        if (p) {
            filterp->id = p->cputype;
            filterp->options = (void *)&p->options;
            return;
        }
    }

    mrb_raise(mrb, E_TYPE_ERROR, "filter type error");
}

/*
 * class LZMA::Encoder
 */

static void
enc_s_encode_args(MRB, VALUE *src, VALUE *dest, mrb_int *maxdest, lzma_filter filters[LZMA_FILTERS_MAX + 1], lzma_check *check, lzma_options_lzma *optlzma)
{
    mrb_int argc;
    VALUE *argv;
    mrb_get_args(mrb, "*", &argv, &argc);

    memset(filters, 0, sizeof(lzma_filter[LZMA_FILTERS_MAX + 1]));
    memset(optlzma, 0, sizeof(*optlzma));
    if (argc > 0 && mrb_hash_p(argv[argc - 1])) {
        argc --;
        VALUE preset, acheck;
        MRBX_SCANHASH(mrb, argv[argc], Qnil,
                MRBX_SCANHASH_ARGS("preset", &preset, Qnil),
                MRBX_SCANHASH_ARGS("check", &acheck, Qnil));
        *check = aux_to_check(mrb, acheck);

        filters[0].id = LZMA_FILTER_LZMA2;
        filters[0].options = (void *)optlzma;

        uint32_t t = (NIL_P(preset) ? LZMA_PRESET_DEFAULT : aux_to_u32(mrb, preset));
        aux_check_preset(mrb, lzma_lzma_preset(optlzma, t));
    } else {
        filters[0].id = LZMA_FILTER_LZMA2;
        filters[0].options = (void *)optlzma;
        lzma_lzma_preset(optlzma, LZMA_PRESET_DEFAULT);
        *check = LZMA_CHECK_CRC64;
    }
    filters[1].id = LZMA_VLI_UNKNOWN;

    //mrb_int argc0 = argc;
    argc = aux_args_to_filter(mrb, argc, argv, NULL, filters);

    switch (argc) {
    case 1:
        *maxdest = -1;
        *dest = Qnil;
        break;
    case 2:
        if (mrb_string_p(argv[1])) {
            *maxdest = -1;
            *dest = argv[1];
        } else {
            *maxdest = (NIL_P(argv[1]) ? -1 : mrb_int(mrb, argv[1]));
            *dest = Qnil;
        }
        break;
    case 3:
        *maxdest = (NIL_P(argv[1]) ? -1 : mrb_int(mrb, argv[1]));
        *dest = Qnil;
        break;
    default:
        mrb_raise(mrb, E_ARGUMENT_ERROR,
                  "wrong number of arguments (expect" \
                    " ``(src, dest = \"\", (*filters,) opts = {})'' or" \
                    " ``(src, maxdest, dest = \"\", (*filters,) opts = {})'')");
    }

    *src = argv[0];
    mrb_check_type(mrb, *src, MRB_TT_STRING);

    if (*maxdest < 0) {
        *maxdest = -1;
        *dest = aux_str_resize(mrb, *dest, AUX_LZMA_PARTIAL_SIZE);
    } else {
        *dest = aux_str_resize(mrb, *dest, *maxdest);
    }
}

/*
 * call-seq:
 *  encode(src, dest = "", (*filters,) opts = {}) -> dest
 *  encode(src, maxdest, dest = "", (*filters,) opts = {}) -> dest
 *
 * [opts]
 *  check = :crc64::
 *      Choose :none, :crc32, :crc64, :sha256 or nil.
 *  preset = LZMA::DEFAULT_PRESET::
 *      Set preset for lzma2, if not given filters.
 */
static VALUE
enc_s_encode(MRB, VALUE self)
{
    mrb_int maxdest;
    VALUE src, dest;
    lzma_filter filters[LZMA_FILTERS_MAX + 1];
    lzma_check check;
    lzma_options_lzma optlzma;
    enc_s_encode_args(mrb, &src, &dest, &maxdest, filters, &check, &optlzma);

    lzma_allocator allocator = aux_lzma_allocator(mrb);

    if (maxdest >= 0) {
        size_t destoff = 0;
        lzma_ret s = lzma_stream_buffer_encode(filters, check, &allocator,
                                               (const uint8_t *)RSTRING_PTR(src), RSTRING_LEN(src),
                                               (uint8_t *)RSTRING_PTR(dest), &destoff, maxdest);
        aux_check_error(mrb, s, "lzma_stream_buffer_encode");
        aux_str_set_len(mrb, dest, destoff);
        return dest;
    } else {
        /* 段階的に dest を拡張して伸長する */

        lzma_stream stream = LZMA_STREAM_INIT;
        lzma_ret s;

        stream.next_in = (const uint8_t *)RSTRING_PTR(src);
        stream.avail_in = RSTRING_LEN(src);
        stream.next_out = (uint8_t *)RSTRING_PTR(dest);
        stream.avail_out = RSTRING_CAPA(dest);
        stream.allocator = &allocator;

        s = lzma_stream_encoder(&stream, filters, check);
        aux_check_error(mrb, s, "lzma_stream_encoder");

        return aux_lzma_code_expand(mrb, &stream, dest);
    }
}

struct encoder
{
    lzma_stream stream;
    lzma_filter filters[LZMA_FILTERS_MAX + 1];
    lzma_allocator allocator;
    //VALUE filterobjects;
    //VALUE outport;
    //VALUE destbuf;
};

static void
encoder_free(MRB, struct encoder *p)
{
    lzma_end(&p->stream);
    mrb_free(mrb, p);
}

static const mrb_data_type encoder_type = {
    .struct_name = "mruby-lzma.encoder",
    .dfree = (void (*)(mrb_state *, void *))encoder_free,
};

static struct encoder *
getencoder(MRB, VALUE self)
{
    return (struct encoder *)getref(mrb, self, &encoder_type);
}

static VALUE
enc_s_new(MRB, VALUE self)
{
    return NEW_OBJECT(mrb, self, &encoder_type, struct encoder, {
        p->allocator = aux_lzma_allocator(mrb);

        {
            static const lzma_stream init = LZMA_STREAM_INIT;
            p->stream = init;
            p->stream.allocator = &p->allocator;
        }

        for (int i = 0; i < ELEMENTOF(p->filters); i ++) {
            p->filters[i].id = LZMA_VLI_UNKNOWN;
            p->filters[i].options = NULL;
        }
    });
}

static void
enc_initialize_args(MRB, VALUE *outport, VALUE *afilters, lzma_filter filters[], lzma_check *check)
{
    mrb_int argc;
    VALUE *argv;
    mrb_get_args(mrb, "*", &argv, &argc);

    VALUE preset;
    if (argc > 0 && mrb_hash_p(argv[argc - 1])) {
        VALUE acheck;
        MRBX_SCANHASH(mrb, argv[argc - 1], Qnil,
                MRBX_SCANHASH_ARGS("preset", &preset, Qnil),
                MRBX_SCANHASH_ARGS("check", &acheck, Qnil));
        *check = aux_to_check(mrb, acheck);
        argc --;
    } else {
        *check = LZMA_CHECK_CRC64;
        preset = Qnil;
    }

    //mrb_int argc0 = argc;
    argc = aux_args_to_filter(mrb, argc, argv, afilters, filters);

    if (NIL_P(*afilters)) {
        struct filter_lzmaX *p;
        *afilters = ALLOCATE_OBJECT(mrb, DIG_MODULE(mrb, NULL, "LZMA", "LZMA2"), struct filter_lzmaX, &filter_lzma2_type, p);
        uint32_t t = (NIL_P(preset) ? LZMA_PRESET_DEFAULT : aux_to_u32(mrb, preset));
        aux_check_preset(mrb, lzma_lzma_preset(&p->options, t));
        setup_filter(mrb, &filters[0], *afilters);
    }

    switch (argc) {
    case 1:
        break;
    default:
        mrb_raise(mrb, E_ARGUMENT_ERROR,
                  "wrong number of arguments (expect" \
                    " ``(outport, (*filters,) opts = {})'')");
    }

    *outport = argv[0];
}

/*
 * call-seq:
 *  initialize(outport, *(filter,) opts = {})
 */
static VALUE
enc_initialize(MRB, VALUE self)
{
    struct encoder *p = getencoder(mrb, self);
    VALUE outport, filters;
    lzma_check check;
    enc_initialize_args(mrb, &outport, &filters, p->filters, &check);

    VALUE destbuf = mrb_str_buf_new(mrb, AUX_LZMA_PARTIAL_SIZE);

    p->stream.next_in = NULL;
    p->stream.avail_in = 0;
    p->stream.next_out = (uint8_t *)RSTRING_PTR(destbuf);
    p->stream.avail_out = RSTRING_CAPA(destbuf);
    lzma_ret s = lzma_stream_encoder(&p->stream, p->filters, check);

    aux_str_set_len(mrb, destbuf, RSTRING_CAPA(destbuf) - p->stream.avail_out);
    if (RSTRING_LEN(destbuf) > 0) {
        FUNCALLC(mrb, outport, "<<", destbuf);
    }

    aux_check_error(mrb, s, "lzma_stream_encoder");

    aux_set_outport(mrb, self, outport);
    aux_set_filters(mrb, self, filters);
    aux_set_destbuf(mrb, self, destbuf);

    return self;
}

/*
 * call-seq:
 *  write(src) -> self
 */
static VALUE
enc_write(MRB, VALUE self)
{
    VALUE src;
    mrb_get_args(mrb, "S", &src);

    struct encoder *p = getencoder(mrb, self);
    p->stream.next_in = (const uint8_t *)RSTRING_PTR(src);
    p->stream.avail_in = RSTRING_LEN(src);

    VALUE outport = aux_get_outport(mrb, self);
    VALUE destbuf = aux_get_destbuf(mrb, self);
    VALUE gclive = mrb_ary_new(mrb);
    mrb_ary_push(mrb, gclive, destbuf);
    int ai = mrb_gc_arena_save(mrb);

    while (p->stream.avail_in > 0) {
        destbuf = aux_str_reserve(mrb, destbuf, AUX_LZMA_PARTIAL_SIZE);
        mrb_ary_set(mrb, gclive, 0, destbuf);
        mrb_gc_arena_restore(mrb, ai);

        p->stream.next_out = (uint8_t *)RSTRING_PTR(destbuf);
        p->stream.avail_out = RSTRING_CAPA(destbuf);

        lzma_ret s = lzma_code(&p->stream, LZMA_RUN);
        aux_str_set_len(mrb, destbuf, RSTRING_CAPA(destbuf) - p->stream.avail_out);
        if (RSTRING_LEN(destbuf) > 0) {
            FUNCALLC(mrb, outport, "<<", destbuf);
        }

        aux_check_error(mrb, s, "lzma_code");
    }

    aux_set_destbuf(mrb, self, destbuf);

    return self;
}

/*
 * call-seq:
 *  sync(fullsync = false) -> self
 */
static VALUE
enc_sync(MRB, VALUE self)
{
    mrb_bool fullsync = FALSE;
    mrb_get_args(mrb, "|b", &fullsync);
    lzma_action act = (fullsync ? LZMA_FULL_FLUSH : LZMA_SYNC_FLUSH);

    struct encoder *p = getencoder(mrb, self);
    p->stream.next_in = NULL;
    p->stream.avail_in = 0;

    VALUE outport = aux_get_outport(mrb, self);
    VALUE destbuf = aux_get_destbuf(mrb, self);
    VALUE gclive = mrb_ary_new(mrb);
    mrb_ary_push(mrb, gclive, destbuf);
    int ai = mrb_gc_arena_save(mrb);

    do {
        destbuf = aux_str_reserve(mrb, destbuf, AUX_LZMA_PARTIAL_SIZE);
        mrb_ary_set(mrb, gclive, 0, destbuf);
        mrb_gc_arena_restore(mrb, ai);

        p->stream.next_out = (uint8_t *)RSTRING_PTR(destbuf);
        p->stream.avail_out = RSTRING_CAPA(destbuf);

        lzma_ret s = lzma_code(&p->stream, act);

        aux_str_set_len(mrb, destbuf, RSTRING_CAPA(destbuf) - p->stream.avail_out);
        if (RSTRING_LEN(destbuf) > 0) {
            FUNCALLC(mrb, outport, "<<", destbuf);
        }

        if (s == LZMA_STREAM_END) { break; }
        aux_check_error(mrb, s, "lzma_code");
    } while (p->stream.avail_out == 0);

    aux_set_destbuf(mrb, self, destbuf);

    return self;
}

/*
 * call-seq:
 *  close -> nil
 */
static VALUE
enc_close(MRB, VALUE self)
{
    mrb_get_args(mrb, "");

    struct encoder *p = getencoder(mrb, self);
    p->stream.next_in = NULL;
    p->stream.avail_in = 0;

    VALUE outport = aux_get_outport(mrb, self);
    VALUE destbuf = aux_get_destbuf(mrb, self);
    VALUE gclive = mrb_ary_new(mrb);
    mrb_ary_push(mrb, gclive, destbuf);
    int ai = mrb_gc_arena_save(mrb);

    do {
        destbuf = aux_str_reserve(mrb, destbuf, AUX_LZMA_PARTIAL_SIZE);
        mrb_ary_set(mrb, gclive, 0, destbuf);
        mrb_gc_arena_restore(mrb, ai);

        p->stream.next_out = (uint8_t *)RSTRING_PTR(destbuf);
        p->stream.avail_out = RSTRING_CAPA(destbuf);

        lzma_ret s = lzma_code(&p->stream, LZMA_FINISH);

        aux_str_set_len(mrb, destbuf, RSTRING_CAPA(destbuf) - p->stream.avail_out);
        if (RSTRING_LEN(destbuf) > 0) {
            FUNCALLC(mrb, outport, "<<", destbuf);
        }

        if (s == LZMA_STREAM_END) { break; }
        aux_check_error(mrb, s, "lzma_code");
    } while (p->stream.avail_out == 0);

    lzma_end(&p->stream);

    aux_set_destbuf(mrb, self, Qnil);
    aux_set_outport(mrb, self, Qnil);
    aux_set_filters(mrb, self, Qnil);

    return self;
}

static void
init_encoder(MRB, struct RClass *mLZMA)
{
    struct RClass *cEncoder = mrb_define_class_under(mrb, mLZMA, "Encoder", mrb_cObject);
    MRB_SET_INSTANCE_TT(cEncoder, MRB_TT_DATA);
    mrb_define_class_method(mrb, cEncoder, "encode", enc_s_encode, MRB_ARGS_ANY());
    mrb_define_class_method(mrb, cEncoder, "new", enc_s_new, MRB_ARGS_ANY());
    mrb_define_method(mrb, cEncoder, "initialize", enc_initialize, MRB_ARGS_ANY());
    mrb_define_method(mrb, cEncoder, "write", enc_write, MRB_ARGS_ANY());
    mrb_define_method(mrb, cEncoder, "sync", enc_sync, MRB_ARGS_ARG(0, 1));
    mrb_define_method(mrb, cEncoder, "close", enc_close, MRB_ARGS_ANY());
}

/*
 * class LZMA::Decoder
 */

static void
dec_s_decode_args(MRB, VALUE *src, VALUE *dest, mrb_int *maxdest, uint64_t *memlimit, uint32_t *flags)
{
    mrb_int argc;
    VALUE *argv;
    mrb_get_args(mrb, "*", &argv, &argc);
    argc = aux_decoder_options(mrb, argc, argv, memlimit, flags);

    switch (argc) {
    case 1:
        *maxdest = -1;
        *dest = Qnil;
        break;
    case 2:
        if (mrb_string_p(argv[1])) {
            *maxdest = -1;
            *dest = argv[1];
        } else {
            *maxdest = aux_to_u64(mrb, argv[1]);
            *dest = Qnil;
        }
        break;
    case 3:
        *maxdest = aux_to_u64(mrb, argv[1]);
        *dest = argv[2];
        break;
    default:
        mrb_raise(mrb, E_ARGUMENT_ERROR,
                  "wrong number of arguments");
    }

    *src = argv[0];
    mrb_check_type(mrb, *src, MRB_TT_STRING);

    if (*memlimit == 0) {
        *memlimit = UINT64_MAX;
    }

    if (*maxdest == -1) {
        *dest = aux_str_resize(mrb, *dest, AUX_LZMA_PARTIAL_SIZE);
    } else {
        *dest = aux_str_resize(mrb, *dest, *maxdest);
    }
}

/*
 * call-seq:
 *  decode(src, dest = "", opts = {}) -> dest
 *  decode(src, maxdest, dest = "", opts = {}) -> dest
 *
 * [opts]
 *  memlimit = (auto)::
 *      Set usage memory limitasion.
 *  tell_no_check (true OR false)::
 *  tell_unsupported_check (true OR false)::
 *  tell_any_check (true OR false)::
 *  ignore_check (true OR false)::
 *  concatenated (true OR false)::
 */
static VALUE
dec_s_decode(MRB, VALUE self)
{
    VALUE src, dest;
    mrb_int maxdest;
    uint64_t memlimit;
    uint32_t flags;
    dec_s_decode_args(mrb, &src, &dest, &maxdest, &memlimit, &flags);
    lzma_allocator allocator = aux_lzma_allocator(mrb);

    if (maxdest >= 0) {
        lzma_stream stream = LZMA_STREAM_INIT;
        lzma_ret s;

        stream.next_in = (const uint8_t *)RSTRING_PTR(src);
        stream.avail_in = RSTRING_LEN(src);
        stream.next_out = (uint8_t *)RSTRING_PTR(dest);
        stream.avail_out = maxdest;
        stream.allocator = &allocator;

        s = lzma_auto_decoder(&stream, memlimit, flags);
        aux_check_error(mrb, s, "lzma_auto_decoder");

        s = lzma_code(&stream, LZMA_FINISH);
        lzma_end(&stream);

        if (s != LZMA_STREAM_END) {
            aux_check_error(mrb, s, "lzma_code");
        }

        aux_str_set_len(mrb, dest, stream.total_out);

        return dest;
    } else {
        /* 段階的に dest を拡張して伸長する */

        lzma_stream stream = LZMA_STREAM_INIT;
        lzma_ret s;

        stream.next_in = (const uint8_t *)RSTRING_PTR(src);
        stream.avail_in = RSTRING_LEN(src);
        stream.next_out = (uint8_t *)RSTRING_PTR(dest);
        stream.avail_out = RSTRING_CAPA(dest);
        stream.allocator = &allocator;

        s = lzma_auto_decoder(&stream, memlimit, flags);
        aux_check_error(mrb, s, "lzma_auto_decoder");

        return aux_lzma_code_expand(mrb, &stream, dest);
    }
}

struct decoder
{
    lzma_stream stream;
    lzma_allocator allocator;
    size_t offset; /* srcbuf が string オブジェクトの場合の読み込み位置 */
};

static void
decoder_free(MRB, struct decoder *p)
{
    lzma_end(&p->stream);
    mrb_free(mrb, p);
}

static const mrb_data_type decoder_type = {
    .struct_name = "mruby-lzma.decoder",
    .dfree = (void (*)(mrb_state *, void *))decoder_free,
};

static struct decoder *
getdecoder(MRB, VALUE self)
{
    return (struct decoder *)getref(mrb, self, &decoder_type);
}

static VALUE
dec_s_new(MRB, VALUE self)
{
    return NEW_OBJECT(mrb, self, &decoder_type, struct decoder, {
        p->allocator = aux_lzma_allocator(mrb);

        {
            static const lzma_stream init = LZMA_STREAM_INIT;
            p->stream = init;
            p->stream.allocator = &p->allocator;
        }

        p->offset = 0;
    });
}

static void
dec_initialize_args(MRB, VALUE *inport, uint64_t *memlimit, uint32_t *flags)
{
    mrb_int argc;
    VALUE *argv;
    mrb_get_args(mrb, "*", &argv, &argc);
    argc = aux_decoder_options(mrb, argc, argv, memlimit, flags);

    switch (argc) {
    case 1:
        break;
    default:
        mrb_raise(mrb, E_ARGUMENT_ERROR,
                  "wrong number of arguments");
    }

    *inport = argv[0];

    if (*memlimit == 0) {
        *memlimit = UINT64_MAX;
    }
}

/*
 * call-seq:
 *  initialize(inport, opts = {})
 *
 * [opts]
 *  memlimit = (auto)::
 *      Set usage memory limitasion.
 *  tell_no_check (true OR false)::
 *  tell_unsupported_check (true OR false)::
 *  tell_any_check (true OR false)::
 *  ignore_check (true OR false)::
 *  concatenated (true OR false)::
 */
static VALUE
dec_initialize(MRB, VALUE self)
{
    struct decoder *p = getdecoder(mrb, self);
    VALUE inport;
    uint64_t memlimit;
    uint32_t flags;
    dec_initialize_args(mrb, &inport, &memlimit, &flags);

    VALUE srcbuf = aux_read(mrb, inport, AUX_LZMA_PARTIAL_SIZE, Qnil, &p->offset);

    p->stream.next_in = (const uint8_t *)RSTRING_PTR(srcbuf);
    p->stream.avail_in = RSTRING_LEN(srcbuf);
    p->stream.next_out = NULL;
    p->stream.avail_out = 0;
    lzma_ret s = lzma_auto_decoder(&p->stream, memlimit, flags);
    aux_check_error(mrb, s, "lzma_auto_decoder");

    aux_set_inport(mrb, self, inport);
    aux_set_srcbuf(mrb, self, srcbuf);

    return self;
}

/*
 * call-seq:
 *  read(size = nil, dest = "") -> dest
 */
static VALUE
dec_read(MRB, VALUE self)
{
    mrb_int size = -1;
    VALUE dest = Qnil;
    mrb_get_args(mrb, "|iS", &size, &dest);

    if (size == 0) {
        if (NIL_P(dest)) {
            dest = mrb_str_new(mrb, NULL, 0);
        } else {
            RSTR_SET_LEN(RSTRING(dest), 0);
        }
        return dest;
    }

    struct decoder *p = getdecoder(mrb, self);
    VALUE inport = aux_get_inport(mrb, self);
    VALUE gclive = TUPLE(mrb, Qnil, dest); /* [src, dest] の順で格納する */
    int ai = mrb_gc_arena_save(mrb);
    VALUE src = aux_get_srcbuf(mrb, self);
    mrb_ary_set(mrb, gclive, 0, src);

    /* NOTE: src が変更されて next_in などが無効な値になっていないかを確認 */
    if (NIL_P(src)) {
        p->stream.next_in = NULL;
        p->stream.avail_in = 0;
    } else {
        const uint8_t *x = (const uint8_t *)RSTRING_PTR(src);
        const uint8_t *const y = x + RSTRING_LEN(src);
        if (p->stream.next_in < x ||
                p->stream.next_in >= y ||
                p->stream.avail_in > y - x) {
            p->stream.next_in = NULL;
            p->stream.avail_in = 0;
        }
    }

    if (size > 0) {
        dest = aux_str_resize(mrb, dest, size);
    } else {
        dest = aux_str_resize(mrb, dest, AUX_LZMA_PARTIAL_SIZE);
    }
    RSTR_SET_LEN(RSTRING(dest), 0);
    p->stream.next_out = (uint8_t *)RSTRING_PTR(dest);
    p->stream.avail_out = RSTRING_CAPA(dest);

    while (p->stream.avail_out > 0) {
        if (p->stream.avail_in == 0) {
            src = aux_read(mrb, inport, AUX_LZMA_PARTIAL_SIZE, src, &p->offset);
            mrb_ary_set(mrb, gclive, 0, src);
            mrb_gc_arena_restore(mrb, ai);

            if (NIL_P(src)) {
                p->stream.next_in = NULL;
                p->stream.avail_in = 0;
                lzma_ret s = lzma_code(&p->stream, LZMA_FINISH);
                RSTR_SET_LEN(RSTRING(dest), RSTRING_CAPA(dest) - p->stream.avail_out);
                aux_set_srcbuf(mrb, self, src);
                if (s != LZMA_STREAM_END) {
                    aux_check_error(mrb, s, "lzma_code");
                }
                return (RSTRING_LEN(dest) == 0 ? Qnil : dest);
            }

            p->stream.next_in = (const uint8_t *)RSTRING_PTR(src);
            p->stream.avail_in = RSTRING_LEN(src);
        }

        lzma_ret s = lzma_code(&p->stream, LZMA_RUN);
        RSTR_SET_LEN(RSTRING(dest), RSTRING_CAPA(dest) - p->stream.avail_out);
        if (s == LZMA_STREAM_END) { break; }
        if (s != LZMA_OK) {
            aux_set_srcbuf(mrb, self, src);
            aux_check_error(mrb, s, "lzma_code");
        }
        if (size < 0 && p->stream.avail_out < 1) {
            const size_t s1 = RSTRING_LEN(dest);
            dest = aux_str_resize(mrb, dest, RSTRING_CAPA(dest) + AUX_LZMA_PARTIAL_SIZE);
            RSTR_SET_LEN(RSTRING(dest), s1);
            p->stream.next_out = (uint8_t *)RSTRING_PTR(dest) + s1;
            p->stream.avail_out = RSTRING_CAPA(dest) - s1;
        }
    }

    aux_set_srcbuf(mrb, self, src);

    return (RSTRING_LEN(dest) == 0 ? Qnil : dest);
}

/*
 * call-seq:
 *  close -> nil
 */
static VALUE
dec_close(MRB, VALUE self)
{
    struct decoder *p = getdecoder(mrb, self);
    p->stream.next_in = NULL;
    p->stream.avail_in = 0;
    p->stream.next_out = NULL;
    p->stream.avail_out = 0;

    lzma_end(&p->stream);

    aux_set_inport(mrb, self, Qnil);
    aux_set_srcbuf(mrb, self, Qnil);

    return Qnil;
}

static void
init_decoder(MRB, struct RClass *mLZMA)
{
    struct RClass *cDecoder = mrb_define_class_under(mrb, mLZMA, "Decoder", mrb_cObject);
    MRB_SET_INSTANCE_TT(cDecoder, MRB_TT_DATA);
    mrb_define_class_method(mrb, cDecoder, "decode", dec_s_decode, MRB_ARGS_ANY());
    mrb_define_class_method(mrb, cDecoder, "new", dec_s_new, MRB_ARGS_ANY());
    mrb_define_method(mrb, cDecoder, "initialize", dec_initialize, MRB_ARGS_ANY());
    mrb_define_method(mrb, cDecoder, "read", dec_read, MRB_ARGS_ARG(0, 2));
    mrb_define_method(mrb, cDecoder, "close", dec_close, MRB_ARGS_NONE());
}

/*
 * class LZMA::RawEncoder
 */

/*
 * call-seq:
 *  encode(src, dest = "", +(filters,) opts = {}) -> dest
 *  encode(src, maxdest, dest = "", +(filters,) opts = {}) -> dest
 *
 * [opts]
 *  N/A
 */

/*
 * class LZMA::RawDecoder
 */

/*
 * call-seq:
 *  decode(src, dest = "", +(filters,) opts = {}) -> dest
 *  decode(src, maxdest, dest = "", +(filters,) opts = {}) -> dest
 *
 * [opts]
 *  N/A
 */

/*
 * initializer lzma
 * module LZMA
 */

static uint32_t
ext_s_crc32_common(MRB)
{
    VALUE seq = Qnil, acrc = Qnil;
    mrb_int argc = mrb_get_args(mrb, "|So", &seq, &acrc);

    uint32_t crc;

    switch (argc) {
    case 0:
        return 0;
    case 1:
        crc = 0;
        break;
    case 2:
        crc = aux_to_uint64(mrb, acrc);
        break;
    default:
        mrb_bug(mrb, "MUST NOT REACHED HERE");
    }

    return lzma_crc32((const uint8_t *)RSTRING_PTR(seq), RSTRING_LEN(seq), crc);
}

/*
 * call-seq:
 *  crc32 -> 0
 *  crc32(seq, crc = 0) -> crc
 */
static VALUE
ext_s_crc32(MRB, VALUE self)
{
    return aux_conv_uint64(mrb, ext_s_crc32_common(mrb), 4);
}

/*
 * call-seq:
 *  crc32_hexdigest -> "00000000"
 *  crc32_hexdigest(seq, crc = 0) -> crc
 */
static VALUE
ext_s_crc32_hexdigest(MRB, VALUE self)
{
    return aux_conv_hexdigest(mrb, ext_s_crc32_common(mrb), 4);
}

static uint64_t
ext_s_crc64_common(MRB)
{
    VALUE seq = Qnil, acrc = Qnil;
    mrb_int argc = mrb_get_args(mrb, "|So", &seq, &acrc);

    uint64_t crc;

    switch (argc) {
    case 0:
        return 0;
    case 1:
        crc = 0;
        break;
    case 2:
        crc = aux_to_uint64(mrb, acrc);
        break;
    default:
        mrb_bug(mrb, "MUST NOT REACHED HERE");
    }

    return lzma_crc64((const uint8_t *)RSTRING_PTR(seq), RSTRING_LEN(seq), crc);
}

/*
 * call-seq:
 *  crc64 -> 0
 *  crc64(seq, crc = 0) -> crc
 */
static VALUE
ext_s_crc64(MRB, VALUE self)
{
    return aux_conv_uint64(mrb, ext_s_crc64_common(mrb), 8);
}

/*
 * call-seq:
 *  crc64_hexdigest -> "0000000000000000"
 *  crc64_hexdigest(seq, crc = 0) -> crc
 */
static VALUE
ext_s_crc64_hexdigest(MRB, VALUE self)
{
    return aux_conv_hexdigest(mrb, ext_s_crc64_common(mrb), 8);
}

void
mrb_mruby_lzma_gem_init(MRB)
{
    struct RClass *mLZMA = mrb_define_module(mrb, "LZMA");

    init_filter(mrb, mLZMA);
    init_encoder(mrb, mLZMA);
    init_decoder(mrb, mLZMA);

    mrb_define_class_method(mrb, mLZMA, "crc32", ext_s_crc32, MRB_ARGS_ARG(0, 2));
    mrb_define_class_method(mrb, mLZMA, "crc32_hexdigest", ext_s_crc32_hexdigest, MRB_ARGS_ARG(0, 2));
    mrb_define_class_method(mrb, mLZMA, "crc64", ext_s_crc64, MRB_ARGS_ARG(0, 2));
    mrb_define_class_method(mrb, mLZMA, "crc64_hexdigest", ext_s_crc64_hexdigest, MRB_ARGS_ARG(0, 2));

    (void)aux_get_filters; /* for compiler warning */
}

void
mrb_mruby_lzma_gem_final(MRB)
{
}
