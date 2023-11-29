CC=clang
AFLCC=afl-clang-fast
CFLAGS=-Wall -Wextra -Werror

.PHONY: all clean

all: target target_dbg target_instrumented target_persistent libtarget_libfuzzer.a target_libfuzzer

target: target.c t.c
	$(CC) $(CFLAGS) -DNO_VERB -o $@ $<

target_dbg: target.c t.c
	$(CC) $(CFLAGS) -g -o $@ $<

target_instrumented: target.c t.c
	# don't use UBSan, or use -fsanitize=undefined-trap-on-error
	# so that we are sure to get a crash in libafl
	AFL_USE_UBSAN=0 $(AFLCC) $(CFLAGS) -o $@ $<

target_persistent: target_persistent.c t.c
	AFL_USE_UBSAN=0 $(AFLCC) $(CFLAGS) -DNO_VERB -o $@ $<

target_libfuzzer: target_libfuzzer.c t.c
	# see https://github.com/AFLplusplus/AFLplusplus/blob/stable/utils/aflpp_driver/README.md
	# afl-clang-fast will automatically link with libAFLDriver.a
	# which allows use of normal libfuzzer code with afl++
	AFL_USE_UBSAN=0 $(AFLCC) $(CFLAGS) -DNO_VERB -fsanitize=fuzzer -o $@ $<

target_libfuzzer.o: target_libfuzzer.c t.c
	$(CC) -c -fPIE -fsanitize-coverage=trace-pc-guard $(CFLAGS) -DNO_VERB -o $@ $<

libtarget_libfuzzer.a: target_libfuzzer.o
	# this target we can link against our libafl binary
	llvm-ar rc $@ $^

t.c: names.txt gen_name_lookup.py
	python3 gen_name_lookup.py > $@

clean:
	rm -f t.c
	rm -f target target_dbg target_instrumented target_persistent target_libfuzzer
	rm -f *.o *.a
