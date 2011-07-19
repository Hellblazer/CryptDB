#!/usr/bin/gnuplot

set terminal pdf font "Times New Roman,6" size 4.4in,1.5in dashed dashlength 0.5
set output 'fig/queries.pdf'

set pointsize 0.5
set origin 0,0
set multiplot

set size 0.5,1
set origin 0,0

set key bottom right
set xlabel "No. of Clients"
set ytics 400
set ylabel "Queries / sec" offset +1,0
plot 'fig/queries.dat' using 1:4 title "Postgres" with lp lc rgb 'black' lt 2 \
    ,'fig/queries.dat' using 1:6 title "CryptDB" with lp lc rgb 'red' lt 1 \
   #,'fig/queries.dat' using 1:2 title "Unoptimized CryptDB" with lp

set key bottom right
set size 0.5,1
set origin 0.5,0
set xlabel "No. of Clients"
set ylabel "msec / query" offset +1,0
set ytics 5
plot 'fig/queries.dat' using 1:5 title "Postgres" with lp lc rgb 'black' lt 2 \
    ,'fig/queries.dat' using 1:7 title "CryptDB" with lp lc rgb 'red' lt 1 \
   #,'fig/queries.dat' using 1:3 title "Unoptimized CryptDB" with lp

