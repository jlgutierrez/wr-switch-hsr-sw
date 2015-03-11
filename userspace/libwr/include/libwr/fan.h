#ifndef __LIBWR_FAN_H
#define __LIBWR_FAN_H
#include <libwr/hal_shmem.h>

#define SHW_FAN_UPDATETO_DEFAULT 5

int shw_init_fans(void);
void shw_update_fans(struct hal_temp_sensors *sensors);

#endif /* __LIBWR_FAN_H */
