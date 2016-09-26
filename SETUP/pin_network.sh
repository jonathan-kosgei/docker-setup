#!/bin/bash

Q[0]=1
Q[1]=2
Q[2]=4
Q[3]=8
Q[4]=10
Q[5]=20
Q[6]=40
Q[7]=80

I=0
grep eth0- /proc/interrupts |while read a b; do
  IRQ=$(echo $a |cut -f 1 -d :);
  echo ${Q[$I]} |sudo tee /proc/irq/$IRQ/smp_affinity;
  echo $I ${Q[$I]};
  I=$[${I}+1];
done
