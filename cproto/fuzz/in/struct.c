struct Point {
    int x;
    int y;
};

typedef struct Point Point;

void set_point(Point *p, int x, int y);
Point get_origin(void);
