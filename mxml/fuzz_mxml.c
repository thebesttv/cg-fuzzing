/*
 * Fuzzing harness for Mini-XML parser (v4.x API)
 * Reads XML from a file and parses it using mxml's API
 */
#include <stdio.h>
#include <stdlib.h>
#include "mxml.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <xml_file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    /* Create default options */
    mxml_options_t *options = mxmlOptionsNew();

    /* Load XML document using v4 API */
    mxml_node_t *tree = mxmlLoadFile(NULL, options, fp);
    fclose(fp);

    if (options) {
        mxmlOptionsDelete(options);
    }

    if (tree) {
        /* Walk through the tree */
        mxml_node_t *node;
        for (node = mxmlWalkNext(tree, tree, MXML_DESCEND_ALL);
             node != NULL;
             node = mxmlWalkNext(node, tree, MXML_DESCEND_ALL)) {
            /* Access node type and content */
            mxml_type_t type = mxmlGetType(node);
            const char *text = mxmlGetText(node, NULL);
            const char *element = mxmlGetElement(node);
            (void)type;
            (void)text;
            (void)element;
        }

        /* Free the XML tree */
        mxmlDelete(tree);
    }

    return 0;
}
