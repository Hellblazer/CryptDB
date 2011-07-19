#!/usr/bin/gnuplot

set terminal pdf font "Times New Roman,6" size 2.1in,1.5in dashed dashlength 0.5
set output 'fig/trantput.pdf'

set xlabel "No. of Clients"
set ylabel "Transactions/sec" offset +2,0
set key bottom right
set pointsize 0.5
plot 'fig/trantput.dat' using 1:3 title "Postgres" with lp lc rgb 'black' lt 2, \
     'fig/trantput.dat' using 1:4 title "CryptDB" with lp lc rgb 'red' lt 1
