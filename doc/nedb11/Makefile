TEX	 := $(wildcard *.tex)

all:	paper.pdf

paper.pdf: $(TEX) $(wildcard *.bib)
	pdflatex paper
	bibtex -min-crossrefs=100 paper
	pdflatex paper
	pdflatex paper

clean:
	rm -f paper.aux paper.out paper.blg paper.log paper.bbl paper.pdf

spell:
	for i in $(TEX); do aspell -p ./aspell.words -c $$i; done
	for i in $(TEX); do perl bin/double.pl $$i; done
	for i in $(TEX); do perl bin/abbrv.pl  $$i; done
	bash bin/weasel.sh  $(TEX)
	bash bin/passive.sh $(TEX)
	( head -1 aspell.words ; tail -n +2 aspell.words | sort ) > aspell.words~
	mv aspell.words~ aspell.words

