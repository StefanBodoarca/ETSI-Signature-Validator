#!/bin/bash
while getopts k:o:c: option
do
	case "${option}"
	in
	k) IN_FILE=${OPTARG};;
	o) OUT_FILE=${OPTARG};;
	c) CONFIG_FILE=${OPTARG};;
	esac
done

openssl req -new -key $IN_FILE -out $OUT_FILE -config $CONFIG_FILE