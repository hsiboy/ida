#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <idsa_internal.h>


/****************************************************************************/

#define MAX_TIME INT_MAX
#define STACK 32		/* BG: 2^32/1.45 should be enough elements for most people */

struct tree_node {
  struct tree_node *n_left, *n_right;	/* branches of tree */
  struct tree_node *n_next, *n_prev;	/* links of queue */
  time_t n_timeout;		/* queue timeout */
  signed char n_balance;	/* balance for tree */
  IDSA_UNIT *n_unit;		/* data (ouch, inefficient) */
};
typedef struct tree_node TREE_NODE;

struct tree_root {
  char r_name[IDSA_M_NAME];	/* name of variable */
  unsigned int r_type;		/* type */
  int r_size;			/* number of elements */
  int r_timeout;		/* how many seconds to keep */
  char r_file[IDSA_M_FILE];	/* persistence */
  int r_fd;			/* associated file descriptor */

  struct tree_node *r_root;	/* root of tree */
  struct tree_node *r_head, *r_tail;	/* circular queue */

  struct tree_root *r_next;	/* linked list of trees */
};
typedef struct tree_root TREE_ROOT;

struct tree_handle {
  struct tree_root *t_tree;
  char t_name[IDSA_M_NAME];	/* unit name to be inserted */
  int t_number;			/* unit number (if any) to be inserted */
};
typedef struct tree_handle TREE_HANDLE;

/****************************************************************************/

static TREE_ROOT *tree_new(char *name, unsigned int type, int size, int timeout, char *file);
static void tree_free(TREE_ROOT * root);

static void tree_safe(TREE_ROOT * root);
static void tree_chop(TREE_ROOT * root);
static void tree_expire(TREE_ROOT * root, time_t now);
static void tree_move(TREE_ROOT * root, TREE_NODE * node);
static TREE_NODE *tree_alloc(TREE_ROOT * root);

static void tree_insert(TREE_ROOT * root, IDSA_UNIT * unit, time_t now);
static int tree_find(TREE_ROOT * root, IDSA_UNIT * unit, time_t now);

static TREE_HANDLE *handle_new(char *name, TREE_ROOT * root);
static void handle_free(TREE_HANDLE * handle);
static TREE_ROOT *root_find(TREE_ROOT * root, char *name);
static unsigned int find_type(IDSA_RULE_CHAIN * c, char *name, char *type);
static TREE_HANDLE *handle_make(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, TREE_ROOT ** p);

static int tree_load(TREE_ROOT * root);
static int tree_save(TREE_ROOT * root);

#ifdef TRACE
void tree_dump(TREE_NODE * node, int d, FILE * fp);
int tree_check(TREE_NODE * node);
#endif

/****************************************************************************/

static TREE_ROOT *tree_new(char *name, unsigned int type, int size, int timeout, char *file)
{
  TREE_ROOT *root;
  TREE_NODE *node;
  int i;

  root = malloc(sizeof(TREE_ROOT));
  if (root == NULL) {
    return NULL;
  }
  strncpy(root->r_name, name, IDSA_M_NAME - 1);
  root->r_name[IDSA_M_NAME - 1] = '\0';

  root->r_type = type;
  root->r_size = size;
  root->r_timeout = timeout;

  if (file) {
    strncpy(root->r_file, file, IDSA_M_FILE - 1);
    root->r_file[IDSA_M_FILE - 1] = '\0';
#ifdef O_NOFOLLOW
    root->r_fd = open(root->r_file, O_RDWR | O_CREAT | O_NOCTTY | O_NOFOLLOW, S_IRUSR | S_IWUSR);
#else
    root->r_fd = open(root->r_file, O_RDWR | O_CREAT | O_NOCTTY, S_IRUSR | S_IWUSR);
#endif
  } else {
    root->r_fd = (-1);
  }

  root->r_root = NULL;
  root->r_head = NULL;
  root->r_tail = NULL;

  root->r_next = NULL;

  for (i = 0; i < root->r_size; i++) {	/* allocate circular queue */
    node = malloc(sizeof(TREE_NODE));
    if (node == NULL) {
      tree_free(root);
      return NULL;
    }
    node->n_left = NULL;
    node->n_right = NULL;

    if (i == 0) {
      root->r_head = node;
      root->r_tail = node;

      node->n_next = node;
      node->n_prev = node;
    } else {
      node->n_next = root->r_tail;
      node->n_prev = root->r_tail->n_prev;

      root->r_tail->n_prev = node;
      node->n_prev->n_next = node;
    }

    node->n_unit = idsa_unit_new(name, type, NULL);
    if (node->n_unit == NULL) {
      tree_free(root);
      return NULL;
    }
  }

  tree_load(root);

#ifdef TRACE
  fprintf(stderr, "tree_new(): allocated tree of %d-1 elements\n", size);
#endif

  return root;
}

static void tree_free(TREE_ROOT * root)
{
  TREE_NODE *alpha, *beta;

  tree_save(root);

  if (root) {
    if (root->r_head) {		/* zap circle */
      alpha = root->r_head;
      do {
	beta = alpha;
	alpha = alpha->n_next;
	if (beta->n_unit) {
	  idsa_unit_free(beta->n_unit);
	  beta->n_unit = NULL;
	}
	free(beta);
      } while (alpha != root->r_head);
      root->r_root = NULL;
      root->r_head = NULL;
      root->r_tail = NULL;
    }
    free(root);
  }
}

static void tree_safe(TREE_ROOT * root)
{
  if (root->r_head->n_next == root->r_tail) {
#ifdef TRACE
    fprintf(stderr, "tree_safe(): calling chop\n");
#endif
    tree_chop(root);
#ifdef TRACE
    tree_dump(root->r_root, 0, stderr);
#endif
  }
}

static void tree_chop(TREE_ROOT * root)
{
  TREE_NODE *node, *parent, *child, *target;
  TREE_NODE *stack[STACK];
  int compare[STACK];
  int sp = 0;
  int tp = 0;
  int wants;

#ifdef TRACE
  if (root->r_head == root->r_tail) {
    fprintf(stderr, "tree_chop(): attempting to delete from an empty queue\n");
    abort();
    return;
  }
#endif

  target = root->r_tail;
  root->r_tail = target->n_next;

  /* FIXME: target->n_timeout should be MAX_TIME to survive clock changes */

#ifdef TRACE
  fprintf(stderr, "tree_chop(): should delete %p\n", target);
#endif

  /* find target */
  stack[sp] = root->r_root;
#ifdef TRACE
  fprintf(stderr, "tree_chop(): %p ", stack[sp]);
#endif
  while (stack[sp]) {
    compare[sp] = idsa_unit_compare(target->n_unit, stack[sp]->n_unit);
    if (compare[sp] & IDSA_COMPARE_MORE) {
      stack[sp + 1] = stack[sp]->n_right;
#ifdef TRACE
      fprintf(stderr, "r %p ", stack[sp + 1]);
#endif
    } else if (compare[sp] & IDSA_COMPARE_LESS) {
      stack[sp + 1] = stack[sp]->n_left;
#ifdef TRACE
      fprintf(stderr, "l %p ", stack[sp + 1]);
#endif
    } else {
#ifdef TRACE
      fprintf(stderr, "FOUND ");
#endif
      stack[sp + 1] = NULL;
#ifdef TRACE
      if (stack[sp] != target) {
	fprintf(stderr, "tree_chop(): assertion failure - found duplicate item\n");
	abort();
      }
#endif
      tp = sp;
    }
    sp++;
  }
  /* INVARIANT: top of stack null, underneath the target node */

#ifdef TRACE
  if (sp <= 0 || stack[sp - 1] != target) {
    fprintf(stderr, "tree_chop(): ouch, target %p not found in tree\n", target);
    abort();
  }
#endif

  /* find node to exchange with target */
  if (target->n_left) {
    compare[sp - 1] = IDSA_COMPARE_LESS;
    stack[sp] = target->n_left;
#ifdef TRACE
    fprintf(stderr, "l %p ", stack[sp]);
#endif
    while (stack[sp]->n_right) {
      compare[sp] = IDSA_COMPARE_MORE;
      stack[sp + 1] = stack[sp]->n_right;
      sp++;
#ifdef TRACE
      fprintf(stderr, "r %p ", stack[sp]);
#endif
    }
  } else if (target->n_right) {
    compare[sp - 1] = IDSA_COMPARE_MORE;
    stack[sp] = target->n_right;
#ifdef TRACE
    fprintf(stderr, "r %p ", stack[sp]);
#endif
    while (stack[sp]->n_left) {
      compare[sp] = IDSA_COMPARE_LESS;
      stack[sp + 1] = stack[sp]->n_left;
      sp++;
#ifdef TRACE
      fprintf(stderr, "l %p ", stack[sp]);
#endif
    }
  } else {
    sp--;
  }
#ifdef TRACE
  fprintf(stderr, "\n");
#endif

  if (sp == 0) {		/* only one node, deletion is simple */
#ifdef TRACE
    fprintf(stderr, "tree_chop(): deleting entire tree\n");
#endif
    root->r_root = NULL;
    return;
  }

  /* INVARIANT: top of stack now node to be exchanged, or target itself */
#ifdef TRACE
  fprintf(stderr, "tree_chop(): found target %p[%d], exchange %p[%d]\n", stack[tp], tp, stack[sp], sp);
#endif

  /* if target has leaves exchange */
  if (stack[sp] != target) {	/* can't just exchange payload as timer queue uses pointer */

    /* first remove exchange from tree */
    if (stack[sp - 1]->n_right == stack[sp]) {
      if (stack[sp]->n_right) {
	node = stack[sp]->n_right;
      } else {
	node = stack[sp]->n_left;
      }
      stack[sp - 1]->n_right = node;
    } else {			/* stack[sp-1]->n_left==stack[sp] */
      if (stack[sp]->n_left) {
	node = stack[sp]->n_left;
      } else {
	node = stack[sp]->n_right;
      }
      stack[sp - 1]->n_left = node;
    }
#ifdef TRACE
    fprintf(stderr, "tree_chop(): removed %p, parent now <%p [%p] %p>\n", stack[sp], stack[sp - 1]->n_left, stack[sp - 1], stack[sp - 1]->n_right);
#endif
    /* now exchange completely removed from tree */

    /* replace target with change */
    if (tp) {
      if (compare[tp - 1] & IDSA_COMPARE_MORE) {
	stack[tp - 1]->n_right = stack[sp];
      } else {
	stack[tp - 1]->n_left = stack[sp];
      }
    } else {
      root->r_root = stack[sp];
    }
    stack[sp]->n_right = stack[tp]->n_right;
    stack[sp]->n_left = stack[tp]->n_left;
    stack[sp]->n_balance = stack[tp]->n_balance;
    stack[tp] = stack[sp];
    stack[sp] = node;
    /* now target completely replaced by exchange */

  } else {			/* target has no children, no exchange needed */
    stack[sp] = NULL;
  }
  wants = 1;
#ifdef TRACE
  fprintf(stderr, "tree_chop(): immediate parent %p[%d] with balance %d\n", stack[sp - 1], sp - 1, stack[sp - 1]->n_balance);
#endif

  /* now stack[sp-1] possibly off balance after having its balance updated */

  while (sp && wants) {
    node = stack[sp];
    sp--;
    parent = stack[sp];
#ifdef TRACE
    fprintf(stderr, "tree_chop(): going up %p[%d] with balance %d\n", parent, sp, parent->n_balance);
#endif
    if (compare[sp] & IDSA_COMPARE_MORE) {
      parent->n_right = node;	/* WARNING: correct for previous rotation */
      parent->n_balance--;

      switch (parent->n_balance) {
      case 0:			/* lost one in height, go up to see if a problem */
	wants = 1;
	break;
      case -1:			/* ok, used to be balanced, now just slightly off */
	wants = 0;
	break;
      case -2:			/* problem, do rotation */
	node = parent->n_left;	/* WARNING: rotations happen on other side */
#ifdef TRACE
	fprintf(stderr, "tree_chop(): considering parent %p, child %p for rotation\n", parent, node);
#endif
	if (node->n_balance <= 0) {
#ifdef TRACE
	  fprintf(stderr, "tree_chop(): [%p] left single imbalance\n", parent);
#endif
	  parent->n_left = node->n_right;
	  node->n_right = parent;

	  if (node->n_balance < 0) {
	    wants = 1;
	    parent->n_balance = 0;
	    node->n_balance = 0;
	  } else {
	    wants = 0;
	    parent->n_balance = (-1);
	    node->n_balance = 1;
	  }
	  stack[sp] = node;
	} else {
	  wants = 1;
#ifdef TRACE
	  fprintf(stderr, "tree_chop(): [%p] left double imbalance\n", parent);
#endif
	  child = node->n_right;

	  parent->n_left = child->n_right;
	  node->n_right = child->n_left;

	  child->n_right = parent;
	  child->n_left = node;

	  if (child->n_balance < 0)
	    parent->n_balance = 1;
	  else
	    parent->n_balance = 0;

	  if (child->n_balance > 0)
	    node->n_balance = (-1);
	  else
	    node->n_balance = 0;

	  child->n_balance = 0;
	  stack[sp] = child;
	}
	break;
      }
    } else {
      parent->n_left = node;	/* WARNING: correct for previous rotation */
      parent->n_balance++;
      switch (parent->n_balance) {
      case 0:			/* lost one in height, go up to see if a problem */
	wants = 1;
	break;
      case 1:			/* ok, used to be balanced, now just slightly off */
	wants = 0;
	break;
      case 2:			/* problem, do rotation */
	node = parent->n_right;	/* WARNING: rotations happen on other side */
	if (node->n_balance >= 0) {
#ifdef TRACE
	  fprintf(stderr, "tree_chop(): [%p] right single imbalance\n", parent);
#endif
	  parent->n_right = node->n_left;
	  node->n_left = parent;

	  if (node->n_balance > 0) {
	    wants = 1;
	    parent->n_balance = 0;
	    node->n_balance = 0;
	  } else {
	    wants = 0;
	    parent->n_balance = 1;
	    node->n_balance = (-1);
	  }
	  stack[sp] = node;
	} else {
	  wants = 1;
#ifdef TRACE
	  fprintf(stderr, "tree_chop(): [%p] right double imbalance\n", parent);
#endif
	  child = node->n_left;

	  parent->n_right = child->n_left;
	  node->n_left = child->n_right;

	  child->n_left = parent;
	  child->n_right = node;

	  if (child->n_balance > 0)
	    parent->n_balance = (-1);
	  else
	    parent->n_balance = 0;

	  if (child->n_balance < 0)
	    node->n_balance = 1;
	  else
	    node->n_balance = 0;

	  child->n_balance = 0;
	  stack[sp] = child;
	}
	break;
      }
    }
  }

#ifdef TRACE
  fprintf(stderr, "tree_chop(): final fixup at level %d\n", sp);
#endif

  if (sp) {
    node = stack[sp];
    sp--;
    parent = stack[sp];
    if (compare[sp] & IDSA_COMPARE_MORE) {
      parent->n_right = node;
    } else {
      parent->n_left = node;
    }
  } else {
    root->r_root = stack[0];
  }

}

static TREE_NODE *tree_alloc(TREE_ROOT * root)
{
  TREE_NODE *node;

#ifdef TRACE
  if (root->r_head->n_next == root->r_tail) {
    fprintf(stderr, "tree_alloc(): failure - unable to alloc, should have made safe\n");
    abort();
    return NULL;
  }
#endif

  node = root->r_head;
  root->r_head = node->n_next;

  node->n_left = NULL;
  node->n_right = NULL;
  node->n_balance = 0;

  return node;
}

static void tree_expire(TREE_ROOT * root, time_t now)
{
  TREE_NODE *node;

  if (root->r_head == root->r_tail) {
#ifdef TRACE
    fprintf(stderr, "tree_expire(): tree is empty\n");
#endif
    /* nothing to do for empty tree */
    return;
  }

  node = root->r_head->n_prev;

  if (node->n_timeout < now) {
#ifdef TRACE
    fprintf(stderr, "tree_expire(): timeout of entire tree: timeout=%d, time=%d\n", (int) node->n_timeout, (int) now);
#endif
    root->r_tail = root->r_head;
    root->r_root = NULL;
  } else {
    while (root->r_tail->n_timeout < now) {
#ifdef TRACE
      fprintf(stderr, "tree_expire(): timeout of tail %p: timeout=%d, time=%d\n", root->r_tail, (int) root->r_tail->n_timeout, (int) now);
      fprintf(stderr, "tree_expire(): calling chop\n");
#endif
      tree_chop(root);
    }
  }
}

static void tree_move(TREE_ROOT * root, TREE_NODE * node)
{
  TREE_NODE *prev, *next;
#ifdef TRACE
  int i;
#endif

#ifdef TRACE
  if (root->r_head == root->r_tail) {
    fprintf(stderr, "tree_move(): can not move element %p of an empty queue\n", node);
    abort();
  }
#endif

  if (root->r_head->n_prev != node) {	/* if not at front then work to do */

    if (root->r_tail == node) {	/* if last node update tail pointer */
      root->r_tail = root->r_tail->n_next;
    }

    /* chop out node from old position */
    prev = node->n_prev;
    next = node->n_next;
    next->n_prev = prev;
    prev->n_next = next;

    /* make room at front */
    next = root->r_head;
    prev = next->n_prev;

    /* insert into new position */
    node->n_prev = prev;
    node->n_next = next;
    prev->n_next = node;
    next->n_prev = node;

    /* head proints at next empty position, stayes unchanged */
  }
#ifdef TRACE
  fprintf(stderr, "tree_move(): queue ");
  node = root->r_head;
  for (i = 0; i < root->r_size; i++) {
    fprintf(stderr, "%p ", node);
    node = node->n_next;

    prev = node->n_prev;
    next = node->n_next;
    if ((prev->n_next != node) || (next->n_prev != node)) {
      fprintf(stderr, "tree_move(): relink failed for %p\n", node);
      abort();
    }
  }
  fprintf(stderr, "\n");
  if (node != root->r_head) {
    fprintf(stderr, "tree_move(): queue lost elements\n");
    abort();
  }
#endif

}

static int tree_find(TREE_ROOT * root, IDSA_UNIT * unit, time_t now)
{
  TREE_NODE *node;
  int compare;

  tree_expire(root, now);

  node = root->r_root;
  while (node) {
    compare = idsa_unit_compare(unit, node->n_unit);
    if (compare & IDSA_COMPARE_MORE) {
      node = node->n_right;
    } else if (compare & IDSA_COMPARE_LESS) {
      node = node->n_left;
    } else {
      return 1;
    }
  }

  return 0;
}

/****************************************************************************/

static int tree_load(TREE_ROOT * root)
{
  struct stat st;
  caddr_t addr;
  IDSA_MEX_STATE *state;
  IDSA_MEX_TOKEN *when, *value;
  IDSA_UNIT *unit;
  time_t tm;
  int result = 0;

  if (root->r_fd == (-1)) {
    return 0;
  }
  if (fstat(root->r_fd, &st) != 0) {
    return -1;
  }
  if (st.st_size == 0) {
    return 0;
  }

  addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, root->r_fd, 0);
  if (addr != MAP_FAILED) {
    state = idsa_mex_buffer(addr, st.st_size);
    if (state) {
      unit = idsa_unit_new(root->r_name, root->r_type, NULL);
      if (unit) {
	when = idsa_mex_get(state);
	value = idsa_mex_get(state);
	while (when && value) {
	  tm = atol(when->t_buf);
	  if (tm + root->r_timeout < tm) {
	    tm = tm - root->r_timeout;
	  }
	  /* FIXME: yuck: if tm==MAX_TIME should subtract timeout */
	  if (idsa_unit_scan(unit, value->t_buf) == 0) {
#ifdef TRACE
	    fprintf(stderr, "tree_load(): inserting %ld:%s\n", (long) tm, when->t_buf);
#endif
	    tree_insert(root, unit, tm);
	  }
	  when = idsa_mex_get(state);
	  value = idsa_mex_get(state);
	}
      } else {
	result = (-1);
      }
      if (idsa_mex_error(state)) {
	result = (-1);
      }
      idsa_mex_close(state);
    } else {
      result = (-1);
    }
    munmap(addr, st.st_size);
  } else {
    result = (-1);
  }

  return result;
}

static int tree_save(TREE_ROOT * root)
{
  char buffer[IDSA_M_MESSAGE];
  TREE_NODE *node;
  int sl, wr, ul;
  int result = 0;

  if (root->r_fd == (-1)) {
    return result;
  }

  ftruncate(root->r_fd, 0);

  node = root->r_tail;
  while (node != root->r_head) {
    sl = snprintf(buffer, IDSA_M_MESSAGE - 16, "%ld \"", node->n_timeout - root->r_timeout);

    ul = idsa_unit_print(node->n_unit, buffer + sl, IDSA_M_MESSAGE - (sl + 2), 1);
    if (ul > 0) {
      sl += ul;
      buffer[sl++] = '"';
      buffer[sl++] = '\n';
      wr = write(root->r_fd, buffer, sl);
      if (wr == sl) {
	node = node->n_next;
      } else {
	/* FIXME: maybe a truncate to undo last write ? */
	result = 1;
	node = root->r_head;
      }
    } else {
      result = 1;
      node = root->r_head;
    }
  }

  close(root->r_fd);
  root->r_fd = (-1);

  return result;
}

/****************************************************************************/

static void tree_insert(TREE_ROOT * root, IDSA_UNIT * unit, time_t now)
{
  TREE_NODE *node, *parent, *child;
  TREE_NODE *stack[STACK];
  int compare[STACK];
  int wants;
  int sp = 0;
  time_t timeout;

  tree_expire(root, now);	/* delete stale entries */
  tree_safe(root);		/* make sure that we have at least one free entry */

  timeout = (root->r_timeout) ? (now + root->r_timeout) : MAX_TIME;

#ifdef TRACE
  fprintf(stderr, "tree_insert(): about to insert, timeout=%d, time=%d\n", (int) timeout, (int) now);
#endif

  stack[sp] = root->r_root;	/* go down tree to build stack */
#ifdef TRACE
  fprintf(stderr, "tree_insert(): %p ", stack[sp]);
#endif
  while (stack[sp]) {
    compare[sp] = idsa_unit_compare(unit, stack[sp]->n_unit);
    if (compare[sp] & IDSA_COMPARE_MORE) {
#ifdef TRACE
      fprintf(stderr, "r %p ", stack[sp]);
#endif
      stack[sp + 1] = stack[sp]->n_right;
    } else if (compare[sp] & IDSA_COMPARE_LESS) {
#ifdef TRACE
      fprintf(stderr, "l %p ", stack[sp]);
#endif
      stack[sp + 1] = stack[sp]->n_left;
    } else {
#ifdef TRACE
      fprintf(stderr, "FOUND\n");
#endif
      stack[sp]->n_timeout = timeout;
      tree_move(root, stack[sp]);
      return;			/* collision - break out */
    }
    sp++;
  }
#ifdef TRACE
  fprintf(stderr, "\n");
#endif

  /* make new entry */
  stack[sp] = tree_alloc(root);
  stack[sp]->n_timeout = timeout;
  idsa_unit_copy(stack[sp]->n_unit, unit);

#ifdef TRACE
  fprintf(stderr, "tree_insert(): created node %p at depth %d with timeout %d\n", stack[sp], sp, (int) (stack[sp]->n_timeout));
#endif

  /* invariant - new node inserted, stack with new node on top and root at bottom */

  /* simple case - first node never needs rotation */
  if (sp == 0) {
    root->r_root = stack[0];
    return;
  }

  /* first parent can never be critically imbalanced, just update its balance */
  node = stack[sp];
  sp--;
  parent = stack[sp];
  if (compare[sp] & IDSA_COMPARE_MORE) {
    parent->n_right = node;
    parent->n_balance++;
  } else {
    parent->n_left = node;
    parent->n_balance--;
  }
  wants = parent->n_balance ? 1 : 0;

  /* rotations start at grandparent */
  while (sp && wants) {
    node = stack[sp];
    sp--;
    parent = stack[sp];
#ifdef TRACE
    fprintf(stderr, "tree_insert(): depth %d with parent %p and child %p\n", sp, parent, node);
#endif
    if (compare[sp] & IDSA_COMPARE_MORE) {
      parent->n_right = node;	/* WARNING: correct for previous rotation */
      parent->n_balance++;

#ifdef TRACE
      fprintf(stderr, "tree_insert(): attaching %p to right of %p, balance %d\n", node, parent, parent->n_balance);
#endif

      switch (parent->n_balance) {
      case 0:			/* just balanced perfectly */
	wants = 0;
	break;
      case 1:			/* possibly ok, continue checking */
	wants = 1;
	break;
      case 2:			/* problem, do rotation */
	wants = 0;
	if (node->n_balance > 0) {
#ifdef TRACE
	  fprintf(stderr, "tree_insert(): [%p] right single imbalance\n", parent);
#endif
	  parent->n_right = node->n_left;
	  node->n_left = parent;

	  parent->n_balance = 0;

	  node->n_balance = 0;
	  stack[sp] = node;
	} else {
#ifdef TRACE
	  fprintf(stderr, "tree_insert(): [%p] right double imbalance\n", parent);
#endif
	  child = node->n_left;

	  parent->n_right = child->n_left;
	  node->n_left = child->n_right;

	  child->n_left = parent;
	  child->n_right = node;

	  if (child->n_balance > 0)
	    parent->n_balance = (-1);
	  else
	    parent->n_balance = 0;

	  if (child->n_balance < 0)
	    node->n_balance = 1;
	  else
	    node->n_balance = 0;

	  child->n_balance = 0;
	  stack[sp] = child;
	}
	break;
      }
    } else {
      parent->n_left = node;
      parent->n_balance--;

#ifdef TRACE
      fprintf(stderr, "tree_insert(): attaching %p to left of %p, balance %d\n", node, parent, parent->n_balance);
#endif

      switch (parent->n_balance) {
      case 0:			/* just balanced perfectly */
	wants = 0;
	break;
      case -1:			/* possibly ok, continue checking */
	wants = 1;
	break;
      case -2:
	wants = 0;
	if (node->n_balance < 0) {
#ifdef TRACE
	  fprintf(stderr, "tree_insert(): [%p] left single imbalance\n", parent);
#endif
	  parent->n_left = node->n_right;
	  node->n_right = parent;

	  parent->n_balance = 0;

	  node->n_balance = 0;
	  stack[sp] = node;
	} else {
#ifdef TRACE
	  fprintf(stderr, "tree_insert(): [%p] left double imbalance\n", parent);
#endif
	  child = node->n_right;

	  parent->n_left = child->n_right;
	  node->n_right = child->n_left;

	  child->n_right = parent;
	  child->n_left = node;

	  if (child->n_balance < 0)
	    parent->n_balance = 1;
	  else
	    parent->n_balance = 0;

	  if (child->n_balance > 0)
	    node->n_balance = (-1);
	  else
	    node->n_balance = 0;

	  child->n_balance = 0;
	  stack[sp] = child;
	}
	break;
      }
    }
  }

#ifdef TRACE
  fprintf(stderr, "tree_insert(): final fixup at level %d\n", sp);
#endif

  if (sp) {
    node = stack[sp];
    sp--;
    parent = stack[sp];
    if (compare[sp] & IDSA_COMPARE_MORE) {
      parent->n_right = node;
    } else {
      parent->n_left = node;
    }
  } else {
    root->r_root = stack[0];
  }

}

#ifdef TRACE

static int tree_check(TREE_NODE * node)
{
  int result, left, right;

  if (node == NULL) {
    result = 0;
  } else {
#ifdef TRACE
    fprintf(stderr, "tree_check(): checking left %p of %p\n", node->n_left, node);
#endif
    left = tree_check(node->n_left);
#ifdef TRACE
    fprintf(stderr, "tree_check(): checking right %p of %p\n", node->n_right, node);
#endif
    right = tree_check(node->n_right);

    if ((right - left) != node->n_balance) {
      fprintf(stderr, "tree_check(): failure: left=%d node=%p:%d right=%d\n", left, node, node->n_balance, right);
      abort();
    }

    result = (left > right) ? left : right;
    result++;
  }

  return result;
}

static void tree_dump(TREE_NODE * node, int d, FILE * fp)
{
  char buffer[IDSA_M_MESSAGE];
  int i;

  if (!node) {
    return;
  }

  for (i = 0; i < d; i++) {
    fputc(' ', fp);
  }

  i = idsa_unit_print(node->n_unit, buffer, IDSA_M_MESSAGE - 1, 1);
  if (i > 0) {
    buffer[i] = '\0';
  } else {
    buffer[0] = '\0';
  }
  fprintf(fp, "%s %d: <%p [%p] %p>\n", buffer, node->n_balance, node->n_left, node, node->n_right);
  tree_dump(node->n_left, d + 2, fp);
  tree_dump(node->n_right, d + 2, fp);

}
#endif

/****************************************************************************/

static TREE_HANDLE *handle_new(char *name, TREE_ROOT * root)
{
  TREE_HANDLE *result;
  result = malloc(sizeof(TREE_HANDLE));
  if (result) {
    strncpy(result->t_name, name, IDSA_M_NAME);
    result->t_name[IDSA_M_NAME - 1] = '\0';

    result->t_tree = root;
    result->t_number = idsa_resolve_request(idsa_resolve_code(result->t_name));
  }
  return result;
}

static void handle_free(TREE_HANDLE * handle)
{
  if (handle) {
    handle->t_tree = NULL;
    free(handle);
  }
}

static TREE_ROOT *root_find(TREE_ROOT * root, char *name)
{
  while (root) {
    if (strcmp(name, root->r_name)) {
      root = root->r_next;
    } else {
      return root;
    }
  }
  return NULL;
}

static unsigned int find_type(IDSA_RULE_CHAIN * c, char *name, char *type)
{
  unsigned int implicit, explicit;

  implicit = idsa_resolve_type(IDSA_M_UNKNOWN, name);

  if (type == NULL) {		/* easy case, no competitor */
    if (implicit == IDSA_T_NULL) {
      idsa_chain_error_usage(c, "no type given for \"%s\"", name);
    }
    return implicit;
  }

  explicit = idsa_type_code(type);
  if (explicit == IDSA_T_NULL) {	/* failure of explicit lookup is fatal */
    idsa_chain_error_usage(c, "type \"%s\" for \"%s:%s\" does not exist", type, name, type);
    return implicit;
  }

  /* now explicit always has a non-null value */

  if (implicit == IDSA_T_NULL) {	/* nothing implicit */
    return explicit;
  }

  if (implicit != explicit) {	/* two non-null yet different */
    idsa_chain_error_usage(c, "conflicting types for \"%s:%s\"", name, type);
    return IDSA_T_NULL;
  }

  return explicit;
}
static TREE_HANDLE *handle_make(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, TREE_ROOT ** p)
{
  IDSA_MEX_TOKEN *variable, *name, *type, *token, *size, *timeout;
  unsigned int typeval, sizeval, timeval;
  TREE_ROOT *root, *tree;
  TREE_HANDLE *handle;
  char *file;

  name = idsa_mex_get(m);
  variable = idsa_mex_get(m);
  if (variable == NULL || name == NULL) {
    idsa_chain_error_mex(c, m);
    return NULL;
  }

  if (variable->t_id == IDSA_PARSE_COLON) {
    type = idsa_mex_get(m);
    variable = idsa_mex_get(m);
    if (type == NULL || variable == NULL) {
      idsa_chain_error_mex(c, m);
      return NULL;
    }
    typeval = find_type(c, name->t_buf, type->t_buf);
  } else {
    typeval = find_type(c, name->t_buf, NULL);
  }
  if (typeval == IDSA_T_NULL) {
    idsa_chain_error_usage(c, "need a type for \"%s\" on line %d", name->t_buf, name->t_line);
    return NULL;
  }

  size = NULL;
  timeout = NULL;
  sizeval = 2;
  timeval = 0;
  file = NULL;

  token = idsa_mex_get(m);
  while (token && (token->t_id == IDSA_PARSE_COMMA)) {
    token = idsa_mex_get(m);
    if (token) {
      if (!strcmp("size", token->t_buf)) {
	size = idsa_mex_get(m);
	if (size == NULL) {
	  idsa_chain_error_mex(c, m);
	  return NULL;
	}
	sizeval = atoi(size->t_buf);
	if (sizeval < 1) {
	  idsa_chain_error_usage(c, "variable \"%s\" on line %d needs a positive size", token->t_buf, token->t_line);
	  return NULL;
	}
	sizeval++;
      } else if (!strcmp("timeout", token->t_buf)) {
	timeout = idsa_mex_get(m);
	if (timeout == NULL) {
	  idsa_chain_error_mex(c, m);
	  return NULL;
	}
	timeval = atoi(timeout->t_buf);
      } else if (!strcmp("file", token->t_buf)) {
	timeout = idsa_mex_get(m);
	if (timeout == NULL) {
	  idsa_chain_error_mex(c, m);
	  return NULL;
	}
	file = timeout->t_buf;
      } else {
	idsa_chain_error_usage(c, "unknown option \"%s\" for keep module on line %d", token->t_buf, token->t_line);
	return NULL;
      }
      /* try to get next comma */
      token = idsa_mex_get(m);
    } else {
      idsa_chain_error_mex(c, m);
      return NULL;
    }
  }

  if (token != NULL) {
    idsa_mex_unget(m, token);
  }
#ifdef TRACE
  fprintf(stderr, "handle_make(): variable=%s, field name=%s\n", variable->t_buf, name->t_buf);
#endif

  root = *p;
  tree = root_find(root, variable->t_buf);
  if (tree) {
    if (typeval != root->r_type) {
      idsa_chain_error_usage(c, "conflicting types for variable \"%s\" on line %d", variable->t_buf, variable->t_line);
      return NULL;
    }
    if ((timeout && (timeval != root->r_timeout))
	|| (size && (sizeval != root->r_size))
	|| (file && strcmp(file, root->r_file))
	) {
      idsa_chain_error_usage(c, "conflicting options for variable \"%s\" on line %d", variable->t_buf, variable->t_line);
      return NULL;
    }
  } else {
    tree = tree_new(variable->t_buf, typeval, sizeval, timeval, file);
    if (tree == NULL) {
      idsa_chain_error_malloc(c, sizeof(TREE_ROOT) + sizeval * sizeof(TREE_NODE));
      return NULL;
    }
    tree->r_next = root;
    *p = tree;
  }

  handle = handle_new(name->t_buf, tree);
  if (handle == NULL) {
    idsa_chain_error_malloc(c, sizeof(TREE_HANDLE));
  }

  return handle;
}

/****************************************************************************/

static void *keep_global_start(IDSA_RULE_CHAIN * c)
{
  TREE_ROOT **pointer;

  pointer = malloc(sizeof(TREE_ROOT *));
  if (pointer == NULL) {
    idsa_chain_error_malloc(c, sizeof(TREE_ROOT *));
    return NULL;
  }

  *pointer = NULL;

  return pointer;
}

static void keep_global_stop(IDSA_RULE_CHAIN * c, void *g)
{
  TREE_ROOT **pointer;
  TREE_ROOT *alpha, *beta;

  pointer = g;

  if (pointer) {
    alpha = *pointer;
    while (alpha) {
      beta = alpha;
      alpha = alpha->r_next;
      tree_free(beta);
    }
    free(pointer);
  }
}

/****************************************************************************/

static void *keep_test_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  return handle_make(m, c, g);
}

static int keep_test_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *t)
{
  return 1;
}

static void keep_test_stop(IDSA_RULE_CHAIN * c, void *g, void *t)
{
  handle_free(t);
}

static void *keep_action_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  return handle_make(m, c, g);
}

static int keep_action_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *a)
{
  return 1;
}

static void keep_action_stop(IDSA_RULE_CHAIN * c, void *g, void *a)
{
  handle_free(a);
}

/****************************************************************************/

static int keep_test_do(IDSA_RULE_CHAIN * c, void *g, void *t, IDSA_EVENT * q)
{
  IDSA_UNIT *unit;
  TREE_HANDLE *handle;
  TREE_ROOT *root;

#ifdef TRACE
  char buffer[IDSA_M_MESSAGE];
  int i;
#endif

  handle = t;
  root = handle->t_tree;
  if (handle->t_number < idsa_request_count()) {
    unit = idsa_event_unitbynumber(q, handle->t_number);
  } else {
    unit = idsa_event_unitbyname(q, handle->t_name);
  }

  if (unit == NULL) {
    return 0;
  }
#ifdef TRACE
  i = idsa_unit_print(unit, buffer, IDSA_M_MESSAGE - 1, 1);
  if (i > 0) {
    buffer[i] = '\0';
  } else {
    buffer[0] = '\0';
  }
  fprintf(stderr, "keep_test_do(): should find %s:%d=%s\n", idsa_unit_name_get(unit), handle->t_number, buffer);
  tree_dump(root->r_root, 0, stderr);
#endif

  /* FIXME: should try and grab time from event to save a syscall */
  return tree_find(root, unit, time(NULL));
}


static int keep_action_do(IDSA_RULE_CHAIN * c, void *g, void *a, IDSA_EVENT * q, IDSA_EVENT * p)
{
  IDSA_UNIT *unit;
  TREE_HANDLE *handle;
  TREE_ROOT *root;

  handle = a;
  root = handle->t_tree;

  if (handle->t_number < idsa_request_count()) {
    unit = idsa_event_unitbynumber(q, handle->t_number);
  } else {
    unit = idsa_event_unitbyname(q, handle->t_name);
  }

  if (unit == NULL) {
    return 0;
  }
#ifdef TRACE
  fprintf(stderr, "keep_action_do(): should insert %s:%d\n", idsa_unit_name_get(unit), handle->t_number);
#endif


  /* FIXME: try to get time from event to save a syscall */
  tree_insert(root, unit, time(NULL));

#ifdef TRACE
  tree_dump(root->r_root, 0, stderr);
#endif

  return 0;
}

/****************************************************************************/

/****************************************************************************/
/* Does       : Registers a new module. Usually this function is the same   */
/*              across modules, except for name changes                     */
/* Returns    : Pointer to module structure, or NULL on failure             */

IDSA_MODULE *idsa_module_load_keep(IDSA_RULE_CHAIN * c)
{
  IDSA_MODULE *result;

  result = idsa_module_new_version(c, "keep", IDSA_MODULE_INTERFACE_VERSION);
  if (result) {
    result->global_start = &keep_global_start;
    result->global_stop = &keep_global_stop;

    result->test_start = &keep_test_start;
    result->test_cache = &keep_test_cache;
    result->test_do = &keep_test_do;
    result->test_stop = &keep_test_stop;

    result->action_start = &keep_action_start;
    result->action_cache = &keep_action_cache;
    result->action_do = &keep_action_do;
    result->action_stop = &keep_action_stop;
  }

  return result;
}
