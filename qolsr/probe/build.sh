#compile
gcc -DNDEBUG -g -o extract extract_san.c attribute_json.c -lmmt_core -ldl -ljson -lhiredis -lpcap -lstdc++ -luv
