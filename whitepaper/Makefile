MAIN = main

.PHONY: all clean watch

all: $(MAIN).pdf

$(MAIN).pdf: $(MAIN).tex sections/*.tex references.bib
	pdflatex $(MAIN)
	bibtex $(MAIN)
	pdflatex $(MAIN)
	pdflatex $(MAIN)

clean:
	rm -f *.aux *.bbl *.blg *.log *.out *.toc *.pdf sections/*.aux

watch:
	@echo "Watching for changes..."
	@while true; do \
		inotifywait -q -e modify $(MAIN).tex sections/*.tex references.bib 2>/dev/null || sleep 2; \
		make all; \
	done
