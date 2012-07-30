#ifndef __AT91_SOFTPWM_H
#define __AT91_SOFTPWM_H

#define __AT91_SOFTPWM_IOC_MAGIC		'5'

#define AT91_SOFTPWM_ENABLE	  	_IO(__AT91_SOFTPWM_IOC_MAGIC, 4)
#define AT91_SOFTPWM_DISABLE		_IO(__AT91_SOFTPWM_IOC_MAGIC, 5)
#define AT91_SOFTPWM_SETPOINT		_IO(__AT91_SOFTPWM_IOC_MAGIC, 6)

#endif /*__AT91_SOFTPWM_H*/