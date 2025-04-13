#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <regex.h>

#define BUFFER_SIZE 32768 // 32 KB

void print_hash(unsigned char hash[SHA256_DIGEST_LENGTH]) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        printf("%02x", hash[i]);
    }
}

int sha256_file(const char *filename, unsigned char hash[SHA256_DIGEST_LENGTH]) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Не удалось открыть файл");
        return 1;
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    unsigned char buffer[BUFFER_SIZE];
    size_t bytesRead = 0;

    while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        SHA256_Update(&sha256, buffer, bytesRead);
    }

    SHA256_Final(hash, &sha256);
    fclose(file);
    return 0;
}

void list_files(const char *base_path, const char *relative_path, regex_t *exclude_regex) {
    char full_path[4096];
    snprintf(full_path, sizeof(full_path), "%s/%s", base_path, relative_path);

    DIR *dir = opendir(full_path);
    if (dir == NULL) {
        perror("Не удалось открыть каталог");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        if (exclude_regex && regexec(exclude_regex, entry->d_name, 0, NULL, 0) == 0) continue;

        char rel_path[4096];
        if (strlen(relative_path) == 0) {
            snprintf(rel_path, sizeof(rel_path), "%s", entry->d_name);
        } else {
            snprintf(rel_path, sizeof(rel_path), "%s/%s", relative_path, entry->d_name);
        }

        char abs_path[4097];
        snprintf(abs_path, sizeof(abs_path), "%s/%s", base_path, rel_path);
        struct stat st;

        if (stat(abs_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            // Рекурсивный обход вложенной папки
            list_files(base_path, rel_path, exclude_regex);
        } else if (S_ISREG(st.st_mode)) {
            // Только обычные файлы
            unsigned char hash[SHA256_DIGEST_LENGTH];
            if (sha256_file(abs_path, hash) == 0) {
                printf("%s : ", rel_path);
                print_hash(hash);
                printf("\n");
            } else {
                fprintf(stderr, "Ошибка при обработке файла: %s\n", rel_path);
            }
        }
    }
    closedir(dir);
}

int main(int argc, char *argv[]) {
    const char *dir_path = ".";
    const char *exclude_regex_pattern = NULL;
    regex_t exclude_regex;

    const char *VERSION = "1.0";
    const char *AUTHOR = "Таташев Элси";

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-h") == 0) {
            printf("Утилита для вычисления хэш-сумм всех файлов в директории по алгоритму SHA-256.\n");
            printf("Использование: %s [DIR_PATH] [OPTIONS]\n", argv[0]);
            printf("Опции [OPTIONS]:\n");
            printf("  -h      вывести инструкцию по использованию и описание опций и завершить исполнение\n");
            printf("  -v      вывести информацию о версии и об авторе и завершить исполнение\n");
            printf("[DIR_PATH]    Путь к директории для анализа (по умолчанию текущая)\n");
            return 0;
        }

        else if (strcmp(argv[i], "-v") == 0) {
            printf("mangen v%s\n", VERSION);
            printf("автор: %s\n", AUTHOR);
            return 0;
        }

        else if ((strcmp(argv[i], "-e") == 0) && i + 1 <argc) {
            exclude_regex_pattern = argv[++i];
        }

        else {
            dir_path = argv[i];
        }
    }

    if (exclude_regex_pattern) {
        if (regcomp(&exclude_regex, exclude_regex_pattern, REG_EXTENDED)) {
            fprintf(stderr, "Ошибка компиляции регулярного выражения: %s\n", exclude_regex_pattern);
            return 1;
        }
    }

    list_files(dir_path, "", exclude_regex_pattern ? &exclude_regex : NULL);

    if (exclude_regex_pattern) {
        regfree(&exclude_regex);
    }

    return 0;
}