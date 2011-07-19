#!/usr/bin/gnuplot

set terminal pdf font 'Times New Roman,6' size 3.3in,1.6in
set output 'fig/microbars.pdf'

set style fill pattern 2 border 0
set style data histogram
set style histogram cluster gap 1
set ylabel "Queries / sec" offset +2,-1
set yrange [0:13000]

plot 'fig/microbars.dat' using 2 title "Postgres" with histogram lc rgb 'black', \
     'fig/microbars.dat' using 3 title "CryptDB" with histogram lc rgb 'red', \
     'fig/microbars.dat' using 4:xticlabels(1) title "Strawman" with histogram lc rgb 'black'

