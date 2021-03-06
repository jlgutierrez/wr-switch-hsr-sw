#ifndef WRS_NETWORKING_STATUS_GROUP_H
#define WRS_NETWORKING_STATUS_GROUP_H

#define WRSNETWORKINGSTATUS_OID WRS_OID, 6, 2, 3

#define FORWARD_DELTA 5

#define WRS_SFPS_STATUS_OK 1			/* ok */
#define WRS_SFPS_STATUS_ERROR 2			/* error */
#define WRS_SFPS_STATUS_WARNING 3		/* warning, not used */
#define WRS_SFPS_STATUS_WARNING_NA 4	/* warning, at least one field is
					 * equal to 0 (NA),shouldn't happen in
					 * normal operation */
#define WRS_SFPS_STATUS_BUG 5			/* warning */

#define WRS_ENDPOINT_STATUS_OK 1		/* ok */
#define WRS_ENDPOINT_STATUS_ERROR 2		/* error */
#define WRS_ENDPOINT_STATUS_FR 6		/* ok, first read */

#define WRS_SWCORE_STATUS_OK 1			/* ok */
#define WRS_SWCORE_STATUS_ERROR 2		/* error */
#define WRS_SWCORE_STATUS_FR 6			/* ok, first read */

#define WRS_RTU_STATUS_OK 1			/* ok */
#define WRS_RTU_STATUS_ERROR 2			/* error */
#define WRS_RTU_STATUS_FR 6			/* ok, first read */

struct wrsNetworkingStatus_s {
	int wrsSFPsStatus;
	int wrsEndpointStatus;
	int wrsSwcoreStatus;
	int wrsRTUStatus;
};

extern struct wrsNetworkingStatus_s wrsNetworkingStatus_s;
time_t wrsNetworkingStatus_data_fill(void);
void init_wrsNetworkingStatusGroup(void);

struct ns_pstats {
	/* wrsEndpointStatus */
	uint64_t TXUnderrun;		/* 1 */
	uint64_t RXOverrun;		/* 2 */
	uint64_t RXInvalidCode;		/* 3 */
	uint64_t RXSyncLost;		/* 4 */
	uint64_t RXPfilterDropped;	/* 6 */
	uint64_t RXPCSErrors;		/* 7 */
	uint64_t RXCRCErrors;		/* 10 */
	/* wrsSwcoreStatus */
	/* Too much HP traffic / Per-priority queue full */
	uint64_t RXFrames;		/* 20 */
	uint64_t RXPrio0;		/* 22 */
	uint64_t RXPrio1;		/* 23 */
	uint64_t RXPrio2;		/* 24 */
	uint64_t RXPrio3;		/* 25 */
	uint64_t RXPrio4;		/* 26 */
	uint64_t RXPrio5;		/* 27 */
	uint64_t RXPrio6;		/* 28 */
	uint64_t RXPrio7;		/* 29 */
	uint64_t FastMatchPriority;	/* 33 */
	/* wrsRTUStatus */
	uint64_t RXDropRTUFull;		/* 21 */
};

/* parameters read from dot-config */
struct wrsNetworkingStatus_config {
	int hp_frame_rate;
	int rx_frame_rate;
	int rx_prio_frame_rate;
};

#endif /* WRS_NETWORKING_STATUS_GROUP_H */
