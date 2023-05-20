FILE=client
HEADER=utils
CFLAGS=-std=gnu99 -Wall -fsanitize=address,undefined -Wno-unknown-pragmas
# no-unknown-pragmas for `pragma region` support
LDFLAGS=-fsanitize=address,undefined
LDLIBS=-lpthread -lm -lrt

all: ${FILE}
${FILE}: ${FILE}.c ${HEADER}.h # set dependencies (react if found change)
	@gcc ${CFLAGS} ${LDFLAGS} ${LDLIBS} -o ${FILE} ${FILE}.c

.PHONY = clean all
clean:
	rm ${FILE}