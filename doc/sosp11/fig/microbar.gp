#!/usr/bin/gnuplot

set terminal postscript eps enhanced color "Helvetica" 20
set output 'results-temp.ps'

set size ratio 0.6
set boxwidth 0.85 absolute
set style fill solid 1.00 border -1
set style data histogram
set style histogram cluster gap 1
set ylabel "Queries/sec" offset +2.5,0
set yrange [0:13000]
#set term svg # Create an SVG image
#set output 'file.svg'
#set key off # Unless you really want a key
# For this next line, lw is linewidth (2-4)?
#plot 'microbar.txt' using 2:xticlabels(1) with boxes # lw 2

plot 'microbar.txt' using 2 t "Postgres", '' using 3 t "CryptDB", '' using 4:xticlabels(1) t "Strawman"



 system "epstopdf results-temp.ps"
 system "ps2pdf14 -dPDFSETTINGS=/prepress results-temp.pdf microbar1.pdf"
 system "pdfcrop microbar1.pdf microbars.pdf"
 system "rm results-temp.* microbar1.df"

