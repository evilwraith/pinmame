// license:BSD-3-Clause

#ifndef INC_PROCGAME
#define INC_PROCGAME

/* The P-ROC game CPU as PinMAME's CPU interface sees it (src/cpuintrf.c). The game is a separate
   process (src/procgame), so the CPU runs nothing: it gives the machine MAME's scheduling, vblank
   and timers, as every other machine has them */

extern int procgamecpu_ICount;

void procgamecpu_init(void);
void procgamecpu_reset(void *param);
void procgamecpu_exit(void);
int procgamecpu_execute(int cycles);
unsigned procgamecpu_get_context(void *dst);
void procgamecpu_set_context(void *src);
unsigned procgamecpu_get_reg(int regnum);
void procgamecpu_set_reg(int regnum, unsigned val);
void procgamecpu_set_irq_line(int irqline, int state);
void procgamecpu_set_irq_callback(int (*callback)(int irqline));
const char *procgamecpu_info(void *context, int regnum);

/* Why the procgame machine's game did not start, set in its machine init; empty when it started */
const char *procgame_start_error(void);
unsigned procgamecpu_dasm(char *buffer, unsigned pc);

#endif
