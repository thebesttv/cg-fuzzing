#include <stdio.h>

struct Node {
    int data;
    struct Node* next;
};

void print_list(struct Node* head) {
    while (head != NULL) {
        printf("%d\n", head->data);
        head = head->next;
    }
}

int main() {
    struct Node n1 = {1, NULL};
    print_list(&n1);
    return 0;
}
