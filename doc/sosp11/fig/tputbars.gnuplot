#!/usr/bin/gnuplot

set terminal pdf font 'Times New Roman,6' size 3.3in,1.6in
set output 'fig/tputbars.pdf'

set boxwidth 0.4
set ylabel "Throughput (HTTP Req. / sec)" offset +1.5,0
set auto x
set yrange [0:25]
set style fill solid border -1
set key off

plot 'fig/tputbars.dat' using 2:xticlabels(1) with boxes lc rgb 'gray'

