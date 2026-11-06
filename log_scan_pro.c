/* ============================================================
*   Log Analyzer + Hex Viewer
*  - Reads TEXT logs (IIS, Firewall, exported Event logs)
*  - Reads BINARY files (EVTX, EXE, DLL, PCAP, etc.)
*  - Auto-detects file type and picks the right mode
* ============================================================ */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define MAX_LINE   512
#define HEX_PER_ROW 16

/* ============================================================
*  ===== START: HEX VIEWER MODULE (from Hex Code) =====
*  All functions below this header belong to the hex viewer.
*  ============================================================ */

/*
* hex_dump_file()
* ----------------
* Opens a file in binary mode and prints a classic hex dump:
* offset | 16 bytes in hex | ASCII representation.
* Handles both small and large files with constant memory.
*/
static int hex_dump_file(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        perror("Error opening file (hex mode)");
        return 1;
    }

    /* Print file name and size as a header */
    struct stat st;
    if (fstat(fileno(file), &st) == 0 && S_ISREG(st.st_mode))
        printf("== %s (%ld bytes) ==\n", path, (long)st.st_size);
    else
        printf("== %s ==\n", path);

    unsigned char buffer[HEX_PER_ROW];
    size_t bytesRead;
    unsigned long offset = 0;

    while ((bytesRead = fread(buffer, 1, HEX_PER_ROW, file)) > 0) {
        printf("%08lX  ", offset);

        for (size_t i = 0; i < HEX_PER_ROW; i++) {
            if (i < bytesRead)
                printf("%02X ", buffer[i]);
            else
                printf("   ");

            /* Visual gap after byte 8 */
            if (i == 7)
                printf(" ");
        }

        printf(" |");

        for (size_t i = 0; i < bytesRead; i++) {
            if (buffer[i] >= 32 && buffer[i] <= 126)
                printf("%c", buffer[i]);
            else
                printf(".");
        }

        printf("|\n");
        offset += bytesRead;
    }

    if (fclose(file) != 0) {
        perror("Error closing file (hex mode)");
        return 1;
    }

    return 0;
}

/* ===== END: HEX VIEWER MODULE (from Hex Code) ===== */

/* ============================================================
*  File type detection
*  - Reads the first bytes to decide text vs binary.
*  - Text file: printable chars + whitespace only.
*  - Binary file: contains NUL bytes or non-text control chars.
* ============================================================ */
static int is_binary_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;

    unsigned char buf[512];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    for (size_t i = 0; i < n; i++) {
        unsigned char c = buf[i];
        /* NUL byte → almost certainly binary */
        if (c == 0x00) return 1;
        /* Allow tab, LF, CR, and printable ASCII */
        if (c < 0x09 || (c > 0x0D && c < 0x20) || c > 0x7E)
            return 1;
    }
    return 0;
}

/* ============================================================
*  ===== START: TEXT LOG ANALYZER MODULE =====
*  Searches a text log for a keyword and reports matches.
* ============================================================ */

/*
* analyze_text_log()
* ------------------
* Opens a text log, scans it line by line, and prints every line
* containing the keyword along with its line number.
* Returns the number of alerts, or -1 on error.
*/
static long analyze_text_log(const char *filename, const char *keyword)
{
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        perror("Error opening log file");
        return -1;
    }

    char line[MAX_LINE];
    long line_number = 0;
    long alert_count = 0;
    int  truncated   = 0;

    printf("=============================================\n");
    printf(" Log Analysis : %s\n", filename);
    printf(" Keyword      : %s\n", keyword);
    printf("=============================================\n\n");

    while (fgets(line, sizeof(line), fp) != NULL) {
        line_number++;

        /* Detect oversized lines */
        if (strchr(line, '\n') == NULL && !feof(fp)) {
            int c;
            while ((c = fgetc(fp)) != '\n' && c != EOF) { /* skip */ }
            truncated++;
        }

        if (strstr(line, keyword) != NULL) {
            alert_count++;
            line[strcspn(line, "\r\n")] = '\0';
            printf("[ALERT #%ld] Line %ld: %s\n",
                   alert_count, line_number, line);
        }
    }

    if (ferror(fp)) {
        perror("Error while reading log file");
        fclose(fp);
        return -1;
    }

    fclose(fp);

    printf("\n=============================================\n");
    printf(" Total lines read      : %ld\n", line_number);
    printf(" Total alerts detected : %ld\n", alert_count);
    if (truncated > 0)
        printf(" Lines truncated (>%d bytes): %d\n", MAX_LINE, truncated);
    printf("=============================================\n");

    return alert_count;
}

/* ===== END: TEXT LOG ANALYZER MODULE ===== */

/* ============================================================
*  main() — user-friendly entry point
*  - Shows a banner explaining supported file types.
*  - Auto-detects binary vs text and picks the right module.
* ============================================================ */
int main(int argc, char *argv[])
{
    /* ---- Welcome banner ---- */
    printf("#############################################################\n");
    printf("#        SOC Log Analyzer  +  Hex Viewer (v2.0)            #\n");
    printf("#-----------------------------------------------------------#\n");
    printf("#  Supported file types:                                    #\n");
    printf("#    [TEXT]   .log  .txt  .csv  .json   (IIS, Firewall...)  #\n");
    printf("#    [BINARY] .evtx .exe .dll .bin .pcap .dat               #\n");
    printf("#-----------------------------------------------------------#\n");
    printf("#  Usage:                                                   #\n");
    printf("#    %-55s #\n", "tool.exe <file>                (auto mode)");
    printf("#    %-55s #\n", "tool.exe <file> <keyword>      (text search)");
    printf("#    %-55s #\n", "tool.exe <file> --hex          (force hex)");
    printf("#    %-55s #\n", "tool.exe <file> <kw> --hex     (hex + keyword)");
    printf("#############################################################\n\n");

    if (argc < 2) {
        fprintf(stderr, "Error: missing file argument.\n");
        return 1;
    }

    const char *filename  = argv[1];
    const char *keyword   = NULL;
    int         force_hex = 0;

    /* Parse optional arguments */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--hex") == 0)
            force_hex = 1;
        else
            keyword = argv[i];
    }

    /* Verify the file exists */
    struct stat st;
    if (stat(filename, &st) != 0) {
        perror("Cannot access file");
        return 2;
    }

    int binary = force_hex || is_binary_file(filename);

    /* ---- Decide the mode ---- */
    if (binary) {
        printf("[*] Mode: BINARY / HEX VIEW\n\n");
        return hex_dump_file(filename);   /* <-- Hex module */
    } else {
        printf("[*] Mode: TEXT LOG ANALYSIS\n\n");

        if (keyword == NULL) {
            fprintf(stderr,
                "Error: text mode requires a keyword. "
                "Example: tool.exe access.log 404\n");
            return 3;
        }

        long alerts = analyze_text_log(filename, keyword); /* <-- Text module */
        return (alerts < 0) ? 4 : 0;
    }
}