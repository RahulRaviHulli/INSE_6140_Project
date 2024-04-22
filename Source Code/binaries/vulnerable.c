#include <stdio.h>
#include <stdlib.h>

int main() {
    char input[100];
    
    printf("Enter a filename: ");
    scanf("%s", input);
    
    // Vulnerable code: Using sprintf without proper input validation
    char command[150];
    sprintf(command, "ls -l %s", input);
    system(command);
    
    return 0;
}
