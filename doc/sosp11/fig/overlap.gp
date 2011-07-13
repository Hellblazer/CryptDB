#!/usr/bin/gnuplot

#system "cd .. && java -Xmx256m IStreamSim 1000 100 8 4 0 > plots/out0.dat"
#system "cd .. && java -Xmx256m IStreamSim 1000 100 8 4 0.25 > plots/out1.dat"
#system "cd .. && java -Xmx256m IStreamSim 1000 100 8 4 0.5 > plots/out2.dat"
#system "cd .. && java -Xmx256m IStreamSim 1000 100 8 4 0.75 > plots/out3.dat"
#system "cd .. && java -Xmx256m IStreamSim 1000 100 8 4 1 > plots/out4.dat"

set size 1,1
set terminal postscript colour eps enhanced "NimbusSanL-Regu" fontfile "uhvr8a.pfb"

set output 'results-temp.ps'
set xlabel "Fraction of Bad Nodes"
set ylabel "Success Rate"
set title "Impact of nodes internal in multiple trees\n? nodes, ?:?"
set border
set key left bottom
set logscale x
set pointsize 1.3
#set parametric
#set mxtics 5
#set mytics 0
#set grid xtics ytics mxtics mytics
plot 'data.txt' using 1:2 title "  0% overlap" with lines lw 3,\
     'data.txt' using 1:3 title " 25% overlap" with lines lw 3,\
     'data.txt' using 1:4 title " 50% overlap" with lines lw 3

system "epstopdf results-temp.ps"
system "ps2pdf14 -dPDFSETTINGS=/prepress results-temp.pdf overlap.pdf"
system "rm results-temp.*"
