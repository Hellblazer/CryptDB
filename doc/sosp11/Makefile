TEX	 := $(wildcard *.tex)
FIGS_ODG := $(wildcard fig/*.odg)
FIGS_PDF := $(patsubst %.odg,%.pdf,$(FIGS_ODG))

all:	abstract.txt paper.pdf #paper-compat.pdf

paper.pdf: $(TEX) $(wildcard *.bib) fig/overview.pdf
	pdflatex paper
	bibtex -min-crossrefs=100 paper
	pdflatex paper
	pdflatex paper

paper-compat.pdf: paper.pdf
	ps2pdf13 $< $@

clean:
	rm -f paper.aux paper.blg paper.log paper.bbl paper.pdf paper.out paper-compat.pdf

$(FIGS_PDF): %.pdf: %.odg
	unoconv -f pdf --stdout $< > $@.tmp~
	pdfcrop $@.tmp~ $@
	rm -f $@.tmp~

fig/%.pdf: fig/%.svg
	inkscape -z --export-pdf=$@.pdf14 --export-area-drawing $< && ps2pdf13 $@.pdf14 $@ && cp $@ .missing/$@ || cp .missing/$@ $@

spell:
	for i in $(TEX); do aspell -p ./aspell.words -c $$i; done
	for i in $(TEX); do perl bin/double.pl $$i; done
	for i in $(TEX); do perl bin/abbrv.pl  $$i; done
	bash bin/weasel.sh  $(TEX)
	bash bin/passive.sh $(TEX)
	( head -1 aspell.words ; tail -n +2 aspell.words | sort ) > aspell.words~
	mv aspell.words~ aspell.words

abstract.txt: abstract.tex
	cat abstract.tex | \
	    grep -v ^% | \
	    grep -v '{abstract}' | \
	    sed -e 's,\\name,CryptDB,g' | \
	    sed -e 's,\\%,%,g' | \
	    sed -e 's,{\\em \?,,g' | \
	    sed -e 's,},,g' | \
	    sed -e 's,\$$\\tput\$$,27%,' | \
	    fmt -w72 > abstract.txt

