#include <stdio.h>
#include <stdlib.h>

int main() {
    char filename[100];
    
    printf("Enter a filename: ");
    scanf("%s", filename);
    
    // Safe code: Using user input without concatenation to system calls
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("File not found.\n");
        return 1;
    }
    
    printf("File contents:\n");
    char c;
    while ((c = fgetc(file)) != EOF) {
        printf("%c", c);
    }
    fclose(file);
    
    return 0;
}
