#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MIN_PASSWORD_LENGTH 8
#define MIXER_STRING "ceramirxorrev"  

unsigned char rotate_left(unsigned char value, int shift) {
    return (value << shift) | (value >> (8 - shift));
}

unsigned char rotate_right(unsigned char value, int shift) {
    return (value >> shift) | (value << (8 - shift));
}

unsigned char bit_mirror(unsigned char value) {
    unsigned char mirrored = 0;
    for (int i = 0; i < 8; i++) {
        mirrored |= ((value >> i) & 1) << (7 - i);
    }
    return mirrored;
}

// Encrypt password
char* mix_password(const char* password) {
  size_t pass_len = strlen(password);
  size_t mix_len = strlen(MIXER_STRING);

  if (pass_len + mix_len >= 256) {
      fprintf(stderr, "Error: Password too long!\n");
      exit(1);
  }

  char* mixed_key = malloc(pass_len + 1);
  if (!mixed_key) {
      fprintf(stderr, "Memory allocation error\n");
      exit(1);
  }

  strcpy(mixed_key, password);

  for (size_t i = 0; i < pass_len; i++) {
      mixed_key[i] ^= MIXER_STRING[i % mix_len];
  }

  for (size_t i = 0; i < pass_len - 1; i++) {
      mixed_key[i] ^= mixed_key[i + 1];
  }

  for (size_t i = 0; i < pass_len; i++) {
      if (i % 2 == 0) {
          mixed_key[i] = bit_mirror(mixed_key[i]);
      }
  }

  mixed_key[pass_len] = '\0';
  return mixed_key;
}



void encrypted_text(const char* key, FILE* input, FILE* output) {
    char buf;
    char* mixed_key = mix_password(key); 
    if (!mixed_key) return;

    size_t key_len = strlen(mixed_key);
    size_t i = 0;

    while (fread(&buf, 1, 1, input)) {
        // 1. caesar
        char shifted = (buf + mixed_key[i % key_len]) % 256;

        // 2. XOR
        char xored = shifted ^ mixed_key[i % key_len];

        // 3.  XOR but not XOR
        char final;
        if (i % 2 == 0) {
            final = xored ^ mixed_key[i % key_len];
        } else {
            final = xored ^ mixed_key[key_len - (i % key_len) - 1];
        }

        // 4. Bit shift left
        final = rotate_left(final, mixed_key[i % key_len] % 8);

        // 5. bit mirror
        if (i % 2 == 0) {
            final = bit_mirror(final);
        }

        fwrite(&final, 1, 1, output);
        i++;
    }

    free(mixed_key);

}

void decrypt_text(const char* key, FILE* input, FILE* output) {
    char buf;
    char* mixed_key = mix_password(key); 
    if (!mixed_key) return;

    size_t key_len = strlen(mixed_key);
    size_t i = 0;

    while (fread(&buf, 1, 1, input)) {
        // 1. bit mirror
        if (i % 2 == 0) {
            buf = bit_mirror(buf);
        }

        // 2. bit shift right
        char reversed_rotate = rotate_right(buf, mixed_key[i % key_len] % 8);

        // 3. XOR but not XOR
        char reversed_xor;
        if (i % 2 == 0) {
            reversed_xor = reversed_rotate ^ mixed_key[i % key_len];
        } else {
            reversed_xor = reversed_rotate ^ mixed_key[key_len - (i % key_len) - 1];
        }

        // 4. XOR 
        char reversed_xored = reversed_xor ^ mixed_key[i % key_len];

        // 5. caesar 
        char original = (reversed_xored - mixed_key[i % key_len] + 256) % 256;

        fwrite(&original, 1, 1, output);
        i++;
    }
    free(mixed_key);

}
int validate_input(int encrypt, const char *key, const char *input_file, const char *output_file) {
    if (strlen(key) < MIN_PASSWORD_LENGTH) {
        fprintf(stderr, "Error: Password must be at least %d characters long.\n", MIN_PASSWORD_LENGTH);
        return 0;
    }

    FILE *input = fopen(input_file, "rb");
    if (!input) {
        fprintf(stderr, "Error opening input file\n");
        return 0;
    }
    fseek(input, 0, SEEK_END);
    if (ftell(input) == 0) {
        fprintf(stderr, "Error: Input file is empty\n");
        fclose(input);
        return 0;
    }
    fclose(input);

    FILE *output = fopen(output_file, "wb");
    if (!output) {
        fprintf(stderr, "Error opening output file\n");
        return 0;
    }
    fclose(output);

    return 1; 
}


int parse_args(int argc, char *argv[], int *encrypt, char **key, char **input_file, char **output_file) {
    if (argc < 8) { 
        fprintf(stderr, "Error: Not enough arguments provided\n");
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0) {
            if (*encrypt != -1) {
                fprintf(stderr, "Error: Choose either -s or -d\n");
                return 0;
            }
            *encrypt = 1;
        } else if (strcmp(argv[i], "-d") == 0) {
            if (*encrypt != -1) {
              fprintf(stderr, "Error: Choose either -s or -d\n");
              return 0;
            }
            *encrypt = 0;
        } else if (strcmp(argv[i], "-p") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: No password provided after -p\n");
                return 0;
            }
            *key = argv[++i];
        } else if (strcmp(argv[i], "-i") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: No input file specified after -i\n");
                return 0;
            }
            *input_file = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: No output file specified after -o\n");
                return 0;
            }
            *output_file = argv[++i];
        } else {
            fprintf(stderr, "Error: Unrecognized option %s\n", argv[i]);
            return 0;
        }
    }

    if (*encrypt == -1) {
        fprintf(stderr, "Error: No mode specified\n");
        return 0;
    }

    if (*key == NULL) {
        fprintf(stderr, "Error: Password not specified\n");
        return 0;
    }

    if (*input_file == NULL) {
        fprintf(stderr, "Error: Input file not specified\n");
        return 0;
    }

    if (*output_file == NULL) {
        fprintf(stderr, "Error: Output file not specified\n");
        return 0;
    }

    return 1;
}


int main(int argc, char *argv[]) {
    char *input_file = NULL;
    char *output_file = NULL;
    char *key = NULL;
    int encrypt = -1;

    if (!parse_args(argc, argv, &encrypt, &key, &input_file, &output_file)) {
        fprintf(stderr, "Usage: %s -s | -d -p <password> -i <input file> -o <output file>\n", argv[0]);
        return 1;
    }

    if (!validate_input(encrypt, key, input_file, output_file)) {
        return 1; 
    }

    FILE *input = fopen(input_file, "rb");
    if (!input) {
        fprintf(stderr, "Error: Unable to open input file %s\n", input_file);
        return 1;
    }

    FILE *output = fopen(output_file, "wb");
    if (!output) {
        fprintf(stderr, "Error: Unable to open output file %s\n", output_file);
        fclose(input);
        return 1;
    }

    if (encrypt) {
      encrypted_text(key, input, output);
    } else {
        decrypt_text(key, input, output);
    }
    fclose(input);
    fclose(output);

    return 0;
}
