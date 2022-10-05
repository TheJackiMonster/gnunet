# This Makefile.am is in the public domain
all:
	@echo -e \
"Generate documentation:\n" \
"\tmake full - full documentation with dependency graphs (slow)\n" \
"\tmake fast - fast mode without dependency graphs"

full: gnunet.doxy
	python -c "f=open('../../.version'); print(f'PROJECT_NUMBER = {f.read().split(\"-\")[0]}'); f.close()" > version.doxy
	doxygen $<

fast: gnunet.doxy
	python -c "f=open('../../.version'); print(f'PROJECT_NUMBER = {f.read().split(\"-\")[0]}'); f.close()" > version.doxy
	sed 's/\(HAVE_DOT.*=\).*/\1 NO/' $< | doxygen -

clean:
	rm -rf html
	rm -rf xml

EXTRA_DIST = \
   gnunet.doxy
