#!/bin/bash
while getopts i:o: option
do
	case "${option}"
	in
	i) IN_FILE=${OPTARG};;
	o) OUT_FILE=${OPTARG};;
	esac
done

openssl rsa -in $IN_FILE -pubout -out $OUT_FILE