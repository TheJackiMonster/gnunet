if HAVE_EXPERIMENTAL
 EXP_DIR = \
  rps \
  abd \
  auction
endif

if BUILD_PULSE_HELPERS
CONVERSATION_DIR = conversation
else
if BUILD_GST_HELPERS
CONVERSATION_DIR = conversation
endif
endif

SUBDIRS = \
	template \
	set \
	consensus \
	secretsharing \
	scalarproduct \
  $(CONVERSATION_DIR) \
	$(EXP_DIR)
