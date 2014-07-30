//
//  main.m
//  SimpleTraceTarget
//
//  Created by Grzegorz Milos on 29/07/2014.
//  Copyright (c) 2014 Grzegorz Miłoś. All rights reserved.
//

void b(void)
{
    usleep(200 * 1000);
}

void a(void)
{
    for(int i=0; i<5; i++) {
        b();
    }
    printf("Cycle\n");
}

void breakpoint(void)
{
    a();
}

int main(int argc, const char * argv[])
{
    while(true) {
        breakpoint();
    }
    return 0;
}

