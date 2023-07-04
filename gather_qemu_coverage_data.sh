#!/bin/bash

CAN_PROCEED=1
if [[ ! -z "${OUTPUT_DIR}" ]]; then
	TMP_DIR="${OUTPUT_DIR}"
else
	TMP_DIR=$(mktemp -d)
fi

# for debugging
# mkdir -p $TMP_DIR

if [[ ! -z "${AFL_PATH}" ]]; then
	AFL_QEMU_TRACE="${AFL_PATH}/afl-qemu-trace"
elif [[ ! -z "$(command -v afl-qemu-trace)" ]]; then
	AFL_QEMU_TRACE=$(command -v afl-qemu-trace)
else
	echo "ERR: AFL_PATH must be specified or afl-qemu-trace must be in PATH"
	CAN_PROCEED=0
fi


if [[ -z "${AFL_OUTPUT_DIR}" ]]; then
	echo "ERR: AFL_OUTPUT_DIR must be set"
	# maybe use AFL_CUSTOM_INFO_OUT
	CAN_PROCEED=0
fi

if [[ $# -lt 1 ]]; then
	echo "$0"
	echo "Usage: AFL_OUTPUT_DIR=<afl-output-dir> $0 <command args>"
	echo ""
	echo "      AFL_OUTPUT_DIR: output directory from afl++"
	echo "      AFL_PATH: path to built afl++ project. not necessary if afl++ has been installed"
	echo "      OUTPUT_DIR: path to output traces in"
	CAN_PROCEED=0
fi

# only exit after all of the other warnings and errors have been printed
# so that the user doesn't have to waste time
if [[ $CAN_PROCEED -eq 0 ]]; then
	rm -rf $TMP_DIR
	exit 1
fi

QUEUE_DIR=$(find $AFL_OUTPUT_DIR -type d -name 'queue')

for i in $(find $QUEUE_DIR -type f); do
	TMP_FILE=$(mktemp -p $TMP_DIR)
	echo "$AFL_QEMU_TRACE -d in_asm -D $TMP_FILE $@ < $i"
	$AFL_QEMU_TRACE -d in_asm -D $TMP_FILE $@ < $i
done

echo "$TMP_DIR"
