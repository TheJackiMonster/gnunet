#include "platform.h"
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_reclaim_lib.h"
#include "gnunet_container_lib.h"

int
main (int argc, char *argv[])
{
  struct GNUNET_RECLAIM_AttributeList *al;
  struct GNUNET_RECLAIM_AttributeList *al_two;
  struct GNUNET_RECLAIM_AttributeListEntry *ale;
  char attrname[100];
  char attrdata[100];
  size_t ser_len_claimed;
  size_t ser_len_actual;
  char *ser_data;
  int count = 0;

  al = GNUNET_new (struct GNUNET_RECLAIM_AttributeList);
  for (int i = 0; i < 12; i++)
  {
    memset (attrname, 0, 100);
    memset (attrdata, 0, 100);
    sprintf (attrname, "attr%d", i);
    sprintf (attrdata, "%d", i);
    ale = GNUNET_new (struct GNUNET_RECLAIM_AttributeListEntry);
    ale->attribute = GNUNET_RECLAIM_attribute_new (attrname,
                                                   &GNUNET_RECLAIM_ID_ZERO,
                                                   GNUNET_RECLAIM_ATTRIBUTE_TYPE_STRING,
                                                   attrdata,
                                                   strlen (attrdata));
    GNUNET_CONTAINER_DLL_insert (al->list_head,
                                 al->list_tail,
                                 ale);
  }
  ser_len_claimed = GNUNET_RECLAIM_attribute_list_serialize_get_size (al);
  ser_data = GNUNET_malloc (ser_len_claimed);
  ser_len_actual = GNUNET_RECLAIM_attribute_list_serialize (al,
                                                            ser_data);
  GNUNET_assert (ser_len_claimed == ser_len_actual);
  al_two = GNUNET_RECLAIM_attribute_list_deserialize (ser_data,
                                                      ser_len_actual);
  for (ale = al_two->list_head; NULL != ale; ale = ale->next)
    count++;
  GNUNET_assert (12 == count);
  //GNUNET_assert (-1 != deser_len);
  GNUNET_free (ser_data);
  GNUNET_RECLAIM_attribute_list_destroy (al);
}
