# MIT License
# Copyright (c) 2020 Davide Fassio

CC = g++

I = ./include/sha*.hpp
L = ./lib/sha*.cpp

main: main.cpp $I $L
	$(CC) -o sha main.cpp $L
	clear
