#!/usr/bin/gnuplot

set terminal postscript eps enhanced color "Helvetica" 23
set output 'results-temp.ps'

set size ratio 0.6
set boxwidth 0.4 # Probably 3-5.
set ylabel "Throughput (HTTP Req./sec)" offset +1.5,0
set auto x 
set yrange [0:25]
set style fill solid border -1
#set term svg # Create an SVG image
#set output 'file.svg'
set key off # Unless you really want a key
# For this next line, lw is linewidth (2-4)?
plot 'tputbars.txt' using 2:xticlabels(1) with boxes # lw 2

 system "epstopdf results-temp.ps"
 system "ps2pdf14 -dPDFSETTINGS=/prepress results-temp.pdf trantput1.pdf"
 system "pdfcrop trantput1.pdf tputbars.pdf"
 system "rm results-temp.* trantput1.df"

