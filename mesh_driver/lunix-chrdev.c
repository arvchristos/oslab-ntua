/*
 * lunix-chrdev.c
 *
 * Implementation of character devices
 * for Lunix:TNG
 *
 * < Your name here >
 *
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mmzone.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/delay.h>

#include "lunix.h"
#include "lunix-chrdev.h"
#include "lunix-lookup.h"

/*
 * Global data
 */
struct cdev lunix_chrdev_cdev;

static int digit_num(int inp){
	int n = inp;
	int count = 0;
    do
    {
    	// n = n/10
        n /= 10;
        ++count;
    } while (n !=0);
	return count;
}

/*
 * Just a quick [unlocked] check to see if the cached
 * chrdev state needs to be updated from sensor measurements.
 */
static int lunix_chrdev_state_needs_refresh(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;
	sensor = state->sensor;

	WARN_ON ( !(sensor = state->sensor));


	enum	lunix_msr_enum sensor_type;
	sensor_type = state->type;

	//check timestamps
	//in state struct = uint32_t buf_timestamp;
	//in sensor struct = uint32_t msr_data[type of sensor enum]->last_update
	debug("COMPARISON %ld - %ld\n",sensor->msr_data[sensor_type]->last_update,state->buf_timestamp);
	return (sensor->msr_data[sensor_type]->last_update > state->buf_timestamp);
}

/*
 * Updates the cached state of a character device
 * based on sensor data. Must be called with the
 * character device state lock held.
 */
static int lunix_chrdev_state_update(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;
	uint32_t sens_value,last_update;
	int aker = 0,dekad = 0;
	long human_value;

	sensor = state->sensor;
	enum	lunix_msr_enum sensor_type = state->type;


	if (lunix_chrdev_state_needs_refresh(state)) {

		spin_lock(&sensor->lock);

		sens_value = sensor->msr_data[sensor_type]->values[0];
		last_update = sensor->msr_data[sensor_type]->last_update;

		//format data and pass to state
		//first the timestamps
		state->buf_timestamp = sensor->msr_data[sensor_type]->last_update;
		spin_unlock(&sensor->lock);

		//Then buff limit and buffer value
		switch (sensor_type) {
			case 0:
				human_value = lookup_voltage[sens_value];
			break;
			case 1:
				human_value = lookup_temperature[sens_value];
			break;
			case 2:
				human_value = lookup_light[sens_value];
			break;
		}
		debug("SENSOR VAL = %ld\n",human_value);
		//get integer value
		aker = human_value/1000;
		// get decimal value
		dekad = human_value%1000;

		state->buf_lim = digit_num(aker) + digit_num(dekad) + 2; // +2 for newline and point
		debug("STATE UPDATE limit = %d\n",state->buf_lim);
		//then long to string HOW THE FUCK
		snprintf(state->buf_data,sizeof(state->buf_data),"%d.%d\n",aker,dekad);
		debug("STATE UPDATE string = %s",state->buf_data);

	}
	else{
		debug("NO UPDATE STATE\n");
		return -EAGAIN;
	}

	return 1;
}

/*************************************
 * Implementation of file operations
 * for the Lunix character device
 *************************************/

static int lunix_chrdev_open(struct inode *inode, struct file *filp)
{
	/* Declarations */
	/* ? */
	int ret,minor;
	//	struct lunix_sensor_struct *sensor; Have to associate inode with the required sensor given by the filp parameter
	struct lunix_sensor_struct *sensor;
	struct lunix_chrdev_state_struct *state;

	//Also point state from private_data for future reference without all those container_of() calls
	//maybe in future versions check flags for read only access or any other thing like raw or cooked data

	minor = iminor(inode);
	sensor = &(lunix_sensors[minor/8]);

	debug("entering\n");
	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto out;

	/*
	 * Associate this open file with the relevant sensor based on
	 * the minor number of the device node [/dev/sensor<NO>-<TYPE>]
	 * from inode go to major minor from minor get type and put it in new state struct
	 */

	debug("Got minor = %d for BATT measurement\n",minor);

	//allocate character device private state structure: lunix_chrdev_state_struct. CONNECT THE SENSOR FIELD

	state = kzalloc(sizeof(struct lunix_chrdev_state_struct), GFP_KERNEL); //allocate kernel ram
	if (!state) {
		ret = -22;
		goto out;
	}
	state->type = minor%8;
	state->sensor = sensor; //Allocate chrdev lunix sensor with sensor state struct
	sema_init(&(state->lock),1); //initialize state semaphore

	//Other fields of state are initialized by other functions

	filp->private_data = state; /* for other methods without calling container_of() or iminor()*/
out:
	debug("leaving, with ret = %d\n", ret);
	return ret;
}

static int lunix_chrdev_release(struct inode *inode, struct file *filp)
{	struct lunix_chrdev_state_struct *state;
	state = filp->private_data;
	debug("releasing chrdev %d of type %d\n",iminor(inode) , state->type);
	kfree(filp->private_data);
	return 0;
}

static long lunix_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	/* Why? */

	//the driver does not support ioctl calls so we return -EINVAL simulating the default behaviour (pg 18/35)
	return -EINVAL;
}

static ssize_t lunix_chrdev_read(struct file *filp, char __user *usrbuf, size_t cnt, loff_t *f_pos)
{
	ssize_t ret;

	struct lunix_sensor_struct *sensor;
	struct lunix_chrdev_state_struct *state;

	state = filp->private_data;
	WARN_ON(!state);
	int cur_bytes;

	sensor = state->sensor;
	WARN_ON(!sensor);

	enum	lunix_msr_enum sensor_type = state->type;
	debug("Sensor type %d\n",sensor_type);
	debug("RAW Sensor data= %lld\n", sensor->msr_data[sensor_type]->values[0]);

	if(down_interruptible(&(state->lock))){
		ret = -1;
		goto out;
	};

		if (*f_pos == 0) {
				while (lunix_chrdev_state_update(state) == -EAGAIN) {
					up(&(state->lock));
					//IF wait == 0 or wait == -RESTARTSYS (C like 0=false everything else true)
					if (wait_event_interruptible(sensor->wq, (lunix_chrdev_state_needs_refresh(state)))){
						debug("CAUGHT SIGNAL\n");
						return -ERESTARTSYS;
					}

					/* ? */
					/* The process needs to sleep */
					/* See LDD3, page 153 for a hint */
					if(down_interruptible(&(state->lock))){
						ret = -1;
						goto out;
					};
				}
			}

			cur_bytes = state->buf_lim - *f_pos; //bytes that are available for reading in the same measurement

			if (cnt <= cur_bytes){
				ret = cnt;
			}
			else{
				ret = cur_bytes;
			}

			if (copy_to_user(usrbuf, state->buf_data + *f_pos, ret)) {
					up(&(state->lock));
					return -EFAULT;
				}

			if (ret == cur_bytes)
			{
				*f_pos = 0;
			}
			else{
				*f_pos += cnt; // update fpos only if copy to user was succesful
			}


out:
	up(&(state->lock));
	/* Unlock? */
	return ret;
}

static int lunix_chrdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	return -EINVAL;
}

static struct file_operations lunix_chrdev_fops =
{
  		.owner          = THIS_MODULE,
	.open           = lunix_chrdev_open,
	.release        = lunix_chrdev_release,
	.read           = lunix_chrdev_read,
	.unlocked_ioctl = lunix_chrdev_ioctl,
	.mmap           = lunix_chrdev_mmap
};

int lunix_chrdev_init(void)   // running when insmod
{
	/*
	 * Register the character device with the kernel, asking for
	 * a range of minor numbers (number of sensors * 8 measurements / sensor)
	 * beginning with LINUX_CHRDEV_MAJOR:0
	 */
	int ret;
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;

	debug("initializing character device\n");
	cdev_init(&lunix_chrdev_cdev, &lunix_chrdev_fops);
	lunix_chrdev_cdev.owner = THIS_MODULE;

	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);

	ret = register_chrdev_region(dev_no,lunix_minor_cnt,"lunix");
	if (ret < 0) {
		debug("failed to register region, ret = %d\n", ret);
		goto out;
	}

	ret = cdev_add(&lunix_chrdev_cdev,dev_no,lunix_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device\n");
		goto out_with_chrdev_region;
	}
	debug("completed successfully\n");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
out:
	return ret;
}

void lunix_chrdev_destroy(void) //when rmmod
{
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;

	debug("entering\n");
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	cdev_del(&lunix_chrdev_cdev);
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
	debug("leaving\n");
}
