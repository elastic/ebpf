ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n' "$(1)" "$(2)" "$(if $(3), $(3))";
endif

CFLAGS?=	-g -O2 -fPIC

CPPFLAGS?=	-D_GNU_SOURCE -DELASTIC -I. -I../common -I$(MAKEOBJDIR)/common

# Keep original flags
CDIAGFLAGS+=	-Wa,--fatal-warnings
CDIAGFLAGS+=	-Wall
CDIAGFLAGS+=	-Wcast-align
CDIAGFLAGS+=	-Wcast-qual
CDIAGFLAGS+=	-Wchar-subscripts
CDIAGFLAGS+=	-Wconversion
CDIAGFLAGS+=	-Werror
CDIAGFLAGS+=	-Wextra
CDIAGFLAGS+=	-Wformat=2
CDIAGFLAGS+=	-Winline
CDIAGFLAGS+=	-Wmissing-prototypes
CDIAGFLAGS+=	-Wnested-externs
CDIAGFLAGS+=	-Wempty-body
CDIAGFLAGS+=	-Wformat-y2k
CDIAGFLAGS+=	-Wformat-zero-length
CDIAGFLAGS+=	-Wpointer-sign
CDIAGFLAGS+=	-Wpointer-to-int-cast
CDIAGFLAGS+=	-Wsign-compare
CDIAGFLAGS+=	-Wunused-const-variable
CDIAGFLAGS+=	-Wunused-parameter
CDIAGFLAGS+=	-Wold-style-definition
CDIAGFLAGS+=	-Wpointer-arith
CDIAGFLAGS+=	-Wredundant-decls
CDIAGFLAGS+=	-Wreturn-type
CDIAGFLAGS+=	-Wshadow
CDIAGFLAGS+=	-Wstrict-prototypes
CDIAGFLAGS+=	-Wstrict-overflow
CDIAGFLAGS+=	-Wswitch
CDIAGFLAGS+=	-Wunused-parameter
CDIAGFLAGS+=	-Wwrite-strings

CC?=		cc
M4?=		m4
OBJDIR=		$(MAKEOBJDIR)/libelf

GENSRCS:=	$(OBJDIR)/libelf_fsize.c $(OBJDIR)/libelf_msize.c $(OBJDIR)/libelf_convert.c
GENDEPS:=	$(wildcard *.m4)

SRCS=		elf.c							\
		elf_begin.c						\
		elf_cntl.c						\
		elf_end.c elf_errmsg.c elf_errno.c			\
		elf_data.c						\
		elf_fill.c						\
		elf_flag.c						\
		elf_getarhdr.c						\
		elf_getarsym.c						\
		elf_getbase.c						\
		elf_getident.c						\
		elf_getversion.c					\
		elf_hash.c						\
		elf_kind.c						\
		elf_memory.c						\
		elf_next.c						\
		elf_open.c						\
		elf_rand.c						\
		elf_rawfile.c						\
		elf_phnum.c						\
		elf_shnum.c						\
		elf_shstrndx.c						\
		elf_scn.c						\
		elf_strptr.c						\
		elf_update.c						\
		elf_version.c						\
		gelf_cap.c						\
		gelf_checksum.c						\
		gelf_dyn.c						\
		gelf_ehdr.c						\
		gelf_getclass.c						\
		gelf_fsize.c						\
		gelf_move.c						\
		gelf_phdr.c						\
		gelf_rel.c						\
		gelf_rela.c						\
		gelf_shdr.c						\
		gelf_sym.c						\
		gelf_syminfo.c						\
		gelf_symshndx.c						\
		gelf_xlate.c						\
		libelf_align.c						\
		libelf_allocate.c					\
		libelf_ar.c						\
		libelf_ar_util.c					\
		libelf_checksum.c					\
		libelf_data.c						\
		libelf_ehdr.c						\
		libelf_elfmachine.c					\
		libelf_extended.c					\
		libelf_memory.c						\
		libelf_open.c						\
		libelf_phdr.c						\
		libelf_shdr.c						\
		libelf_xlate.c						\
		$(GENSRCS)

ELFDEFS:=	$(MAKEOBJDIR)/common/sys/elfdefinitions.h
ELFDEPS:=	../common/sys/elfdefinitions.m4

DEPS:=		$(wildcard *.h) $(ELFDEPS)
OBJS:=		$(patsubst %.c,%.o,$(SRCS))

LIBELF_STATIC:=	libelf_pic.a

all: mkdir-objdir $(LIBELF_STATIC)

$(LIBELF_STATIC): $(OBJS)
	$(call msg,AR,$@)
	$(Q)cd $(OBJDIR) && ar rcs $(OBJDIR)/$@ $^

$(OBJS): %.o: %.c GNUmakefile $(ELFDEFS) $(GENSRCS)
	$(call msg,CC,$@)
	$(Q)$(CC) -c $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) $< -o $(OBJDIR)/$(notdir $@)

$(GENSRCS): $(GENDEPS)
	$(call msg,M4,$@)
	$(Q)$(M4) -D SRCDIR=. $(notdir $(@:.c=.m4)) > $@

$(ELFDEFS): $(ELFDEPS)
	$(call msg,M4,$@)
	$(Q)$(M4) -I../common/sys -D SRCDIR=../common/sys elfdefinitions.m4 > $@

mkdir-objdir:
	mkdir -p $(OBJDIR)
	mkdir -p $(MAKEOBJDIR)/common/sys

.PHONY: all mkdir-objdir

.SUFFIXES:
