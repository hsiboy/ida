/* simple/sequence anomaly detector - still under development */

/* 
 * Units are stored in a tree, where the branch from root to next level
 * matches the current unit, and deeper edges match older
 * events. 
 *
 * Each node has a success rate associated with it, the 
 * more often it succeeds, the higher its value. 
 *
 * If an event is considered
 * anomalous depends on how deep into the tree the sequence matches, and 
 * the success rate of the node where the match fails. 
 *
 * Averages and 
 * deviations are nonstandard, they are calculated on a running basis, and 
 * decay:  a_(i+1) = n_(i+1) + a_i * d
 *
 * Older nodes are garbage collected on a LRU basis.
 */

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include <idsa_internal.h>

#define STACK 36		/* increase on machines with more than 4G address space */

#define DEFAULT_DECAY   0.714	/* rate of decay */
#define DEFAULT_HISTORY     7	/* longest sequence/depth of tree */
#define DEFAULT_COUNT      64	/* pool of nodes to be used in tree */
#define DEFAULT_DEVIATION 2.0	/* how far from norm until flagged as odd */

struct tree {
  struct tree *t_left;
  struct tree *t_right;
  int t_balance;
  IDSA_UNIT *t_unit;

  struct tree *t_older;
  struct tree *t_newer;
  struct tree *t_root;
  struct tree *t_back;		/* back is needed for deletion */

  double t_success;
};

struct sequence {
  char s_name[IDSA_M_NAME];
  unsigned int s_type;
  int s_count;			/* number of nodes */

  int s_history;		/* size of history buffer */

  struct tree *s_root;		/* start of lookup tree */
  struct tree *s_new;		/* where new nodes are inserted */
  struct tree *s_old;		/* where old nodes are collected */
  struct tree *s_free;		/* pool of free nodes */

  IDSA_UNIT **s_buffer;		/* history buffer */

  double s_success;		/* for s_root */
  double s_average;		/* running mismatch average */
  double s_variance;		/* running variance * x */
  double s_deviations;		/* number of deviations above which we flag */
  double s_fudge;		/* normalise the average and variance */

  double s_decay_average;	/* how much the running average decays */
  double s_decay_success;	/* how fast t_success decays */
  double s_decay_match;		/* how fast match decays on walk down tree */

  struct sequence *s_next;	/* linked list */
};

struct variable {
  int v_number;
  char v_name[IDSA_M_NAME];
  struct sequence *v_sequence;
};

typedef struct tree TREE;
typedef struct sequence SEQUENCE;
typedef struct variable VARIABLE;

static TREE *tree_find(TREE * root, IDSA_UNIT * unit);
static TREE *tree_insert(TREE * root, TREE * add);
static TREE *tree_delete(TREE * root, TREE * target);

#ifdef TRACE
static void tree_dump(TREE * node, int d, FILE * fp);
static int tree_check(TREE * node);
#endif

static unsigned int find_type(IDSA_RULE_CHAIN * c, char *name, char *type);
static SEQUENCE *find_root(SEQUENCE * seq, char *name);

static SEQUENCE *sequence_new(char *name, unsigned int type, int count, int history, double decay, double deviations);
static void sequence_free(SEQUENCE * s);

static void raise_node(SEQUENCE * s, TREE * t);
static void bubble_node(SEQUENCE * s, TREE * t);

static TREE *grab_node(SEQUENCE * s, TREE * p, IDSA_UNIT * u);

static void shift_history(SEQUENCE * s, IDSA_UNIT * u);
static double sequence_match(SEQUENCE * s);
static void sequence_add(SEQUENCE * s);

static int sequence_do(SEQUENCE * s, IDSA_UNIT * u);

#ifdef TRACE
static void dump_line(TREE * t, FILE * fp);
static void dump_history(SEQUENCE * s, FILE * fp);
static void dump_sequence(TREE * t, FILE * fp);
#endif

/****************************************************************************/

/* custom avl implementation */

static TREE *tree_delete(TREE * root, TREE * target)
{
  TREE *node, *parent, *child;
  TREE *stack[STACK];
  int compare[STACK];
  int sp = 0;
  int tp = 0;
  int wants;

#if TRACE > 1
  fprintf(stderr, "tree_delete(): should delete %p\n", target);
#endif

  /* find target */
  stack[sp] = root;
#if TRACE > 1
  fprintf(stderr, "tree_delete(): %p ", stack[sp]);
#endif
  while (stack[sp]) {
    compare[sp] = idsa_unit_compare(target->t_unit, stack[sp]->t_unit);
    if (compare[sp] & IDSA_COMPARE_MORE) {
      stack[sp + 1] = stack[sp]->t_right;
#if TRACE > 1
      fprintf(stderr, "r %p ", stack[sp + 1]);
#endif
    } else if (compare[sp] & IDSA_COMPARE_LESS) {
      stack[sp + 1] = stack[sp]->t_left;
#if TRACE > 1
      fprintf(stderr, "l %p ", stack[sp + 1]);
#endif
    } else {
#if TRACE > 1
      fprintf(stderr, "FOUND ");
#endif
      stack[sp + 1] = NULL;
#if TRACE > 1
      if (stack[sp] != target) {
	fprintf(stderr, "tree_delete(): assertion failure - found duplicate item\n");
	abort();
      }
#endif
      tp = sp;
    }
    sp++;
  }
  /* INVARIANT: top of stack null, underneath the target node */

#if TRACE > 1
  if (sp <= 0 || stack[sp - 1] != target) {
    fprintf(stderr, "tree_delete(): ouch, target %p not found in tree\n", target);
    abort();
  }
#endif

  /* descend tree to find node to exchange with target */
  if (target->t_left) {
    compare[sp - 1] = IDSA_COMPARE_LESS;
    stack[sp] = target->t_left;
#if TRACE > 1
    fprintf(stderr, "l %p ", stack[sp]);
#endif
    while (stack[sp]->t_right) {
      compare[sp] = IDSA_COMPARE_MORE;
      stack[sp + 1] = stack[sp]->t_right;
      sp++;
#if TRACE > 1
      fprintf(stderr, "r %p ", stack[sp]);
#endif
    }
  } else if (target->t_right) {
    compare[sp - 1] = IDSA_COMPARE_MORE;
    stack[sp] = target->t_right;
#if TRACE > 1
    fprintf(stderr, "r %p ", stack[sp]);
#endif
    while (stack[sp]->t_left) {
      compare[sp] = IDSA_COMPARE_LESS;
      stack[sp + 1] = stack[sp]->t_left;
      sp++;
#if TRACE > 1
      fprintf(stderr, "l %p ", stack[sp]);
#endif
    }
  } else {
    sp--;
  }
#if TRACE > 1
  fprintf(stderr, "\n");
#endif

  if (sp == 0) {		/* only one node, deletion is simple */
#if TRACE > 1
    fprintf(stderr, "tree_delete(): deleting entire tree\n");
#endif
    return NULL;
  }

  /* INVARIANT: top of stack now node to be exchanged, or target itself */
#if TRACE > 1
  fprintf(stderr, "tree_delete(): found target %p[%d], exchange %p[%d]\n", stack[tp], tp, stack[sp], sp);
#endif

  /* if target has leaves exchange */
  if (stack[sp] != target) {	/* can't just exchange payload as pointer may be used elsewhere */

    /* first remove exchange from tree */
    if (stack[sp - 1]->t_right == stack[sp]) {
      if (stack[sp]->t_right) {
	node = stack[sp]->t_right;
      } else {
	node = stack[sp]->t_left;
      }
      stack[sp - 1]->t_right = node;
    } else {			/* stack[sp-1]->t_left==stack[sp] */
      if (stack[sp]->t_left) {
	node = stack[sp]->t_left;
      } else {
	node = stack[sp]->t_right;
      }
      stack[sp - 1]->t_left = node;
    }
#if TRACE > 1
    fprintf(stderr, "tree_delete(): removed %p, parent now <%p [%p] %p>\n", stack[sp], stack[sp - 1]->t_left, stack[sp - 1], stack[sp - 1]->t_right);
#endif
    /* now exchange completely removed from tree */

    /* replace target with change */
    if (tp) {
      if (compare[tp - 1] & IDSA_COMPARE_MORE) {
	stack[tp - 1]->t_right = stack[sp];
      } else {
	stack[tp - 1]->t_left = stack[sp];
      }
    }
    stack[sp]->t_right = stack[tp]->t_right;
    stack[sp]->t_left = stack[tp]->t_left;
    stack[sp]->t_balance = stack[tp]->t_balance;
    stack[tp] = stack[sp];
    stack[sp] = node;
    /* now target completely replaced by exchange */

  } else {			/* target has no children, no exchange needed */
    stack[sp] = NULL;
  }
  wants = 1;
#if TRACE > 1
  fprintf(stderr, "tree_delete(): immediate parent %p[%d] with balance %d\n", stack[sp - 1], sp - 1, stack[sp - 1]->t_balance);
#endif

  /* now stack[sp-1] possibly off balance after having its balance updated */

  while (sp && wants) {
    node = stack[sp];
    sp--;
    parent = stack[sp];
#if TRACE > 1
    fprintf(stderr, "tree_delete(): going up %p[%d] with balance %d\n", parent, sp, parent->t_balance);
#endif
    if (compare[sp] & IDSA_COMPARE_MORE) {
      parent->t_right = node;	/* WARNING: correct for previous rotation */
      parent->t_balance--;

      switch (parent->t_balance) {
      case 0:			/* lost one in height, go up to see if a problem */
	wants = 1;
	break;
      case -1:			/* ok, used to be balanced, now just slightly off */
	wants = 0;
	break;
      case -2:			/* problem, do rotation */
	node = parent->t_left;	/* WARNING: rotations happen on other side */
#if TRACE > 1
	fprintf(stderr, "tree_delete(): considering parent %p, child %p for rotation\n", parent, node);
#endif
	if (node->t_balance <= 0) {
#if TRACE > 1
	  fprintf(stderr, "tree_delete(): [%p] left single imbalance\n", parent);
#endif
	  parent->t_left = node->t_right;
	  node->t_right = parent;

	  if (node->t_balance < 0) {
	    wants = 1;
	    parent->t_balance = 0;
	    node->t_balance = 0;
	  } else {
	    wants = 0;
	    parent->t_balance = (-1);
	    node->t_balance = 1;
	  }
	  stack[sp] = node;
	} else {
	  wants = 1;
#if TRACE > 1
	  fprintf(stderr, "tree_delete(): [%p] left double imbalance\n", parent);
#endif
	  child = node->t_right;

	  parent->t_left = child->t_right;
	  node->t_right = child->t_left;

	  child->t_right = parent;
	  child->t_left = node;

	  if (child->t_balance < 0)
	    parent->t_balance = 1;
	  else
	    parent->t_balance = 0;

	  if (child->t_balance > 0)
	    node->t_balance = (-1);
	  else
	    node->t_balance = 0;

	  child->t_balance = 0;
	  stack[sp] = child;
	}
	break;
      }
    } else {
      parent->t_left = node;	/* WARNING: correct for previous rotation */
      parent->t_balance++;
      switch (parent->t_balance) {
      case 0:			/* lost one in height, go up to see if a problem */
	wants = 1;
	break;
      case 1:			/* ok, used to be balanced, now just slightly off */
	wants = 0;
	break;
      case 2:			/* problem, do rotation */
	node = parent->t_right;	/* WARNING: rotations happen on other side */
	if (node->t_balance >= 0) {
#if TRACE > 1
	  fprintf(stderr, "tree_delete(): [%p] right single imbalance\n", parent);
#endif
	  parent->t_right = node->t_left;
	  node->t_left = parent;

	  if (node->t_balance > 0) {
	    wants = 1;
	    parent->t_balance = 0;
	    node->t_balance = 0;
	  } else {
	    wants = 0;
	    parent->t_balance = 1;
	    node->t_balance = (-1);
	  }
	  stack[sp] = node;
	} else {
	  wants = 1;
#if TRACE > 1
	  fprintf(stderr, "tree_delete(): [%p] right double imbalance\n", parent);
#endif
	  child = node->t_left;

	  parent->t_right = child->t_left;
	  node->t_left = child->t_right;

	  child->t_left = parent;
	  child->t_right = node;

	  if (child->t_balance > 0)
	    parent->t_balance = (-1);
	  else
	    parent->t_balance = 0;

	  if (child->t_balance < 0)
	    node->t_balance = 1;
	  else
	    node->t_balance = 0;

	  child->t_balance = 0;
	  stack[sp] = child;
	}
	break;
      }
    }
  }

#if TRACE > 1
  fprintf(stderr, "tree_delete(): final fixup at level %d\n", sp);
#endif

  if (sp) {
    node = stack[sp];
    sp--;
    parent = stack[sp];
    if (compare[sp] & IDSA_COMPARE_MORE) {
      parent->t_right = node;
    } else {
      parent->t_left = node;
    }
  }

  return stack[0];
}

static TREE *tree_insert(TREE * root, TREE * add)
{
  TREE *node, *parent, *child;
  TREE *stack[STACK];
  int compare[STACK];
  int wants;
  int sp = 0;

  stack[sp] = root;		/* go down tree to build stack */
#if TRACE > 1
  fprintf(stderr, "tree_insert(): %p ", stack[sp]);
#endif
  while (stack[sp]) {
    compare[sp] = idsa_unit_compare(add->t_unit, stack[sp]->t_unit);
    if (compare[sp] & IDSA_COMPARE_MORE) {
#if TRACE > 1
      fprintf(stderr, "r %p ", stack[sp]);
#endif
      stack[sp + 1] = stack[sp]->t_right;
    } else if (compare[sp] & IDSA_COMPARE_LESS) {
#if TRACE > 1
      fprintf(stderr, "l %p ", stack[sp]);
#endif
      stack[sp + 1] = stack[sp]->t_left;
    } else {
#ifdef TRACE
      fprintf(stderr, "tree_insert(): FOUND should not happen\n");
      abort();
#endif
    }
    sp++;
  }
#if TRACE > 1
  fprintf(stderr, "\n");
#endif

  stack[sp] = add;

#if TRACE > 1
  fprintf(stderr, "tree_insert(): created node %p at depth %d\n", stack[sp], sp);
#endif

  /* invariant - new node inserted, stack with new node on top and root at bottom */

  /* simple case - first node never needs rotation */
  if (sp == 0) {
    return stack[0];
  }

  /* first parent can never be critically imbalanced, just update its balance */
  node = stack[sp];
  sp--;
  parent = stack[sp];
  if (compare[sp] & IDSA_COMPARE_MORE) {
    parent->t_right = node;
    parent->t_balance++;
  } else {
    parent->t_left = node;
    parent->t_balance--;
  }
  wants = parent->t_balance ? 1 : 0;

  /* rotations start at grandparent */
  while (sp && wants) {
    node = stack[sp];
    sp--;
    parent = stack[sp];
#if TRACE > 1
    fprintf(stderr, "tree_insert(): depth %d with parent %p and child %p\n", sp, parent, node);
#endif
    if (compare[sp] & IDSA_COMPARE_MORE) {
      parent->t_right = node;	/* WARNING: correct for previous rotation */
      parent->t_balance++;

#if TRACE > 1
      fprintf(stderr, "tree_insert(): attaching %p to right of %p, balance %d\n", node, parent, parent->t_balance);
#endif

      switch (parent->t_balance) {
      case 0:			/* just balanced perfectly */
	wants = 0;
	break;
      case 1:			/* possibly ok, continue checking */
	wants = 1;
	break;
      case 2:			/* problem, do rotation */
	wants = 0;
	if (node->t_balance > 0) {
#if TRACE > 1
	  fprintf(stderr, "tree_insert(): [%p] right single imbalance\n", parent);
#endif
	  parent->t_right = node->t_left;
	  node->t_left = parent;

	  parent->t_balance = 0;

	  node->t_balance = 0;
	  stack[sp] = node;
	} else {
#if TRACE > 1
	  fprintf(stderr, "tree_insert(): [%p] right double imbalance\n", parent);
#endif
	  child = node->t_left;

	  parent->t_right = child->t_left;
	  node->t_left = child->t_right;

	  child->t_left = parent;
	  child->t_right = node;

	  if (child->t_balance > 0)
	    parent->t_balance = (-1);
	  else
	    parent->t_balance = 0;

	  if (child->t_balance < 0)
	    node->t_balance = 1;
	  else
	    node->t_balance = 0;

	  child->t_balance = 0;
	  stack[sp] = child;
	}
	break;
      }
    } else {
      parent->t_left = node;
      parent->t_balance--;

#if TRACE > 1
      fprintf(stderr, "tree_insert(): attaching %p to left of %p, balance %d\n", node, parent, parent->t_balance);
#endif

      switch (parent->t_balance) {
      case 0:			/* just balanced perfectly */
	wants = 0;
	break;
      case -1:			/* possibly ok, continue checking */
	wants = 1;
	break;
      case -2:
	wants = 0;
	if (node->t_balance < 0) {
#if TRACE > 1
	  fprintf(stderr, "tree_insert(): [%p] left single imbalance\n", parent);
#endif
	  parent->t_left = node->t_right;
	  node->t_right = parent;

	  parent->t_balance = 0;

	  node->t_balance = 0;
	  stack[sp] = node;
	} else {
#if TRACE > 1
	  fprintf(stderr, "tree_insert(): [%p] left double imbalance\n", parent);
#endif
	  child = node->t_right;

	  parent->t_left = child->t_right;
	  node->t_right = child->t_left;

	  child->t_right = parent;
	  child->t_left = node;

	  if (child->t_balance < 0)
	    parent->t_balance = 1;
	  else
	    parent->t_balance = 0;

	  if (child->t_balance > 0)
	    node->t_balance = (-1);
	  else
	    node->t_balance = 0;

	  child->t_balance = 0;
	  stack[sp] = child;
	}
	break;
      }
    }
  }

#if TRACE > 1
  fprintf(stderr, "tree_insert(): final fixup at level %d\n", sp);
#endif

  if (sp) {
    node = stack[sp];
    sp--;
    parent = stack[sp];
    if (compare[sp] & IDSA_COMPARE_MORE) {
      parent->t_right = node;
    } else {
      parent->t_left = node;
    }
  }

  return stack[0];
}

static TREE *tree_find(TREE * root, IDSA_UNIT * unit)
{
  TREE *node;
  int compare;

  node = root;
  while (node) {
    compare = idsa_unit_compare(unit, node->t_unit);
    if (compare & IDSA_COMPARE_MORE) {
      node = node->t_right;
    } else if (compare & IDSA_COMPARE_LESS) {
      node = node->t_left;
    } else {
      return node;
    }
  }

  return NULL;
}

#ifdef TRACE
static void tree_dump(TREE * node, int d, FILE * fp)
{
  char buffer[IDSA_M_MESSAGE];
  int i;

  if (!node) {
    return;
  }

  for (i = 0; i < d; i++) {
    fputc(' ', fp);
  }

  i = idsa_unit_print(node->t_unit, buffer, IDSA_M_MESSAGE - 1, 1);
  if (i > 0) {
    buffer[i] = '\0';
  } else {
    buffer[0] = '\0';
  }
  fprintf(fp, "%s %d: <%p [%p] %p>\n", buffer, node->t_balance, node->t_left, node, node->t_right);
  tree_dump(node->t_left, d + 2, fp);
  tree_dump(node->t_right, d + 2, fp);
}

static int tree_check(TREE * node)
{
  int result, left, right;

  if (node == NULL) {
    result = 0;
  } else {
    left = tree_check(node->t_left);
    right = tree_check(node->t_right);

    if ((right - left) != node->t_balance) {
      fprintf(stderr, "tree_check(): failure: left=%d node=%p:%d right=%d\n", left, node, node->t_balance, right);
      abort();
    }

    result = (left > right) ? left : right;
    result++;
  }

  return result;
}
#endif

/****************************************************************************/

static SEQUENCE *sequence_new(char *name, unsigned int type, int count, int history, double decay, double deviations)
{
  SEQUENCE *s;
  TREE *tree;
  int i;

#if TRACE > 1
  if (count <= (history * 2)) {
    fprintf(stderr, "sequence_new(): count needs to be more than twice the size of match\n");
    abort();
  }
  if (history < 2) {
    fprintf(stderr, "sequence_new(): history buffer needs to be at least 2 slots\n");
    abort();
  }
#endif
  s = malloc(sizeof(SEQUENCE));
  if (s) {
    strncpy(s->s_name, name, IDSA_M_NAME - 1);
    s->s_name[IDSA_M_NAME - 1] = '\0';

    s->s_type = type;
    s->s_count = count;
    s->s_history = history;
    s->s_deviations = deviations;
    /* FIXME: more fine tuning here */
    s->s_decay_average = decay;
    s->s_decay_success = decay;
    s->s_decay_match = decay;

    s->s_fudge = (1.0 - s->s_decay_average);

#if TRACE > 1
    fprintf(stderr, "sequence_new(): fudge factor is %f\n", s->s_fudge);
#endif

    s->s_success = 1.0;
    s->s_average = 1.0;
    s->s_variance = 1.0 / s->s_fudge;

    s->s_root = NULL;
    s->s_old = NULL;
    s->s_new = NULL;
    s->s_free = NULL;

    s->s_next = NULL;

    s->s_buffer = NULL;

    for (i = 0; i < s->s_count; i++) {
      tree = malloc(sizeof(TREE));
      if (tree) {
	tree->t_older = NULL;
	tree->t_newer = NULL;
	tree->t_root = NULL;
	tree->t_back = s->s_free;
	s->s_free = tree;

	tree->t_unit = idsa_unit_new(s->s_name, s->s_type, NULL);
	if (tree->t_unit == NULL) {
#if TRACE > 1
	  fprintf(stderr, "sequence_new(): unable to allocate unit\n");
#endif
	  sequence_free(s);
	  return NULL;
	}
      } else {
#if TRACE > 1
	fprintf(stderr, "sequence_new(): unable to allocate node\n");
#endif
	sequence_free(s);
	return NULL;
      }
    }

    s->s_buffer = malloc(sizeof(TREE *) * s->s_history);
    if (s->s_buffer) {
      for (i = 0; i < s->s_history; i++) {
	s->s_buffer[i] = NULL;
      }
      for (i = 0; i < s->s_history; i++) {
	s->s_buffer[i] = idsa_unit_new(s->s_name, s->s_type, NULL);
	if (s->s_buffer[i] == NULL) {
#if TRACE > 1
	  fprintf(stderr, "sequence_new(): unable to allocate unit\n");
#endif
	  sequence_free(s);
	  return NULL;
	}
      }
    } else {
#if TRACE > 1
      fprintf(stderr, "sequence_new(): unable to allocate node\n");
#endif
      sequence_free(s);
      return NULL;
    }
  }
  return s;
}

static void sequence_free(SEQUENCE * s)
{
  TREE *tree;
  int i;
  if (s) {
    if (s->s_buffer) {
      for (i = 0; i < s->s_history; i++) {
	if (s->s_buffer[i]) {
	  idsa_unit_free(s->s_buffer[i]);
	}
      }
      free(s->s_buffer);
      s->s_buffer = NULL;
    }

    tree = s->s_new;
    while (tree) {
      tree->t_root = NULL;
      tree->t_back = s->s_free;
      s->s_free = tree;
      tree = tree->t_older;
      s->s_free->t_older = NULL;
      s->s_free->t_newer = NULL;
    }
    s->s_root = NULL;
    s->s_old = NULL;
    s->s_new = NULL;

    tree = s->s_free;
#if TRACE > 1
    i = s->s_count;
#endif
    while (tree) {
      s->s_free = tree->t_back;
      if (tree->t_unit) {
	idsa_unit_free(tree->t_unit);
      }
      free(tree);
      tree = s->s_free;
#if TRACE > 1
      i--;
#endif
    }
#if TRACE > 1
    if (i != 0) {
      fprintf(stderr, "sequence_free(): ouch, deleted %d nodes too few\n", i);
    }
#endif

  }
}

/****************************************************************************/
/* Does       : moves node to front of newer/older list                     */

static void raise_node(SEQUENCE * s, TREE * t)
{
  TREE *older;
  TREE *newer;

  older = t->t_older;
  newer = t->t_newer;

#if TRACE > 1
  fprintf(stderr, "raise_node(): raising node %p, older %p, newer %p\n", t, older, newer);
#endif

  if (newer) {			/* if there is nothing newer we are already at top of list */

    if (older) {		/* if not last node, update older node */
      older->t_newer = newer;
    } else {			/* otherwise update oldest pointer */
#if TRACE > 1
      if (t != s->s_old) {
	fprintf(stderr, "raise_node(): inconsistent oldest node %p != %p\n", t, s->s_old);
	abort();
      }
#endif
      s->s_old = newer;
    }
    newer->t_older = older;	/* newer always valid */

    t->t_newer = NULL;
    t->t_older = s->s_new;
#if TRACE > 1
    if (s->s_new == NULL) {
      fprintf(stderr, "raise_node(): major failure, list should contain more than 1 element\n");
      abort();
    }
#endif

    s->s_new->t_newer = t;
    s->s_new = t;
  }
}

/****************************************************************************/
/* Does       : moves node one up newer/older list                          */

static void bubble_node(SEQUENCE * s, TREE * t)
{
  TREE *older;
  TREE *newer;
  TREE *exchange;

  exchange = t->t_newer;
  if (exchange) {		/* if not already at top */
    older = t->t_older;
    newer = exchange->t_newer;

#if TRACE > 1
    fprintf(stderr, "bubble_node(): exchanging node %p with %p\n", t, exchange);
#endif

    if (newer)
      newer->t_older = t;
    else
      s->s_new = t;

    if (older)
      older->t_newer = exchange;
    else
      s->s_old = exchange;

    exchange->t_older = older;
    exchange->t_newer = t;

    t->t_older = exchange;
    t->t_newer = newer;
  }
}

/****************************************************************************/

static void shift_history(SEQUENCE * s, IDSA_UNIT * u)
{
  IDSA_UNIT *hold;
  int i;

  hold = s->s_buffer[s->s_history - 1];
  for (i = (s->s_history - 1); i > 0; i--) {
    s->s_buffer[i] = s->s_buffer[i - 1];
  }
  s->s_buffer[0] = hold;
  idsa_unit_copy(hold, u);
}

/****************************************************************************/

#ifdef TRACE

static void dump_history(SEQUENCE * s, FILE * fp)
{
  int i;
  IDSA_UNIT *unit;
  char buffer[IDSA_M_MESSAGE];
  int len;

  fprintf(fp, "dump(h=%d,a=%f,v=%f):", s->s_history, s->s_average, s->s_variance);
  for (i = 0; i < s->s_history; i++) {
    unit = s->s_buffer[i];
    len = idsa_unit_print(unit, buffer, IDSA_M_MESSAGE - 1, 0);
    buffer[len] = '\0';
    fprintf(fp, " [%s]:%d", buffer, i);
  }
  fputc('\n', fp);
}

static void dump_line(TREE * t, FILE * fp)
{
  TREE *list[32];
  char buffer[IDSA_M_MESSAGE];
  int len;
  int i;

  i = 0;
  while (t) {
    list[i] = t;
    t = t->t_back;
    i++;
  }
  while (i > 0) {
    i--;
    t = list[i];
    len = idsa_unit_print(t->t_unit, buffer, IDSA_M_MESSAGE - 1, 0);
    buffer[len] = '\0';
    fprintf(fp, "[%p]%s:%f ", t, buffer, t->t_success);
  }
  fputc('\n', fp);
}

static void dump_sequence(TREE * t, FILE * fp)
{
  TREE *stack[32], *prev;
  int i;

  if (t == NULL) {		/* special case if no sequences in tree */
    return;
  }

  /* iterative case, inorder traversal, printing elements */
  stack[0] = NULL;
  stack[1] = t;
  i = 1;
  prev = NULL;

  while (i > 0) {
    if (stack[i - 1] == prev) {	/* on way in */
      prev = stack[i];
      if (stack[i]->t_left) {	/* go down left further */
	stack[i + 1] = stack[i]->t_left;
	i++;
      } else {			/* no left, print and see if we have a right */
	if (stack[i]->t_root) {
	  dump_sequence(stack[i]->t_root, fp);
	} else {
	  dump_line(stack[i], fp);
	}
	if (stack[i]->t_right) {	/* got a right, take it */
	  stack[i + 1] = stack[i]->t_right;
	  i++;
	} else {		/* no children, reverse */
	  i--;
	}
      }
    } else {			/* on way back */
      if (prev == stack[i]->t_left) {	/* visited left branch, see if we can do right */
	prev = stack[i];
	if (stack[i]->t_root) {
	  dump_sequence(stack[i]->t_root, fp);
	} else {
	  dump_line(stack[i], fp);
	}
	if (stack[i]->t_right) {
	  stack[i + 1] = stack[i]->t_right;
	  i++;
	} else {
	  i--;
	}
      } else {			/* did not visit left branch, must have come back from right, go up */
	prev = stack[i];
	i--;
      }
    }
  }
}

#endif

/****************************************************************************/

static TREE *grab_node(SEQUENCE * s, TREE * p, IDSA_UNIT * u)
{
  TREE *result, *back;

  if (s->s_free == NULL) {	/* no more free nodes, garbage collect the oldest one */

#if TRACE > 1
    fprintf(stderr, "grab_node(): protected sequence:\n");
    dump_line(p, stderr);
#endif

    result = s->s_old;
    while (result->t_root != NULL || (p == result)) {	/* find a leaf */
      result = result->t_newer;
#if TRACE > 1
      if (result == NULL) {	/* should be impossible, leaves = count/2 */
	fprintf(stderr, "grab_node(): ran out of leaves\n");
	abort();
      }
#endif
    }

#if TRACE > 1
    fprintf(stderr, "grab_node(): grabbing leaf %p\n", result);
    dump_line(result, stderr);
#endif

    back = result->t_back;
    if (back == NULL) {
      s->s_root = tree_delete(s->s_root, result);
#if TRACE > 1
      tree_check(s->s_root);
#endif
    } else {
      back->t_root = tree_delete(back->t_root, result);
#if TRACE > 1
      tree_check(back->t_root);
#endif
    }
    raise_node(s, result);
  } else {
    result = s->s_free;
    s->s_free = result->t_back;
#if TRACE > 1
    fprintf(stderr, "grab_node(): new node %p from free pool\n", result);
#endif

    /* insert grabbed node at newest position */
    result->t_newer = NULL;
    result->t_older = s->s_new;
    if (s->s_new) {
      s->s_new->t_newer = result;
    } else {
#if TRACE > 1
      if (s->s_old != NULL) {
	fprintf(stderr, "grab_node(): inconsistency between oldest and newest node\n");
	abort();
      }
#endif
      s->s_old = result;
    }
    s->s_new = result;
  }

  /* be nice and zero out new node */
  result->t_left = NULL;
  result->t_right = NULL;
  result->t_balance = 0;

  result->t_root = NULL;
  result->t_back = NULL;

  result->t_success = s->s_average;
/*  result->t_success=1.0;*/

  idsa_unit_copy(result->t_unit, u);

  return result;
}

static double sequence_match(SEQUENCE * s)
{
  double match;
  int i = 0;
  TREE *tree, *prev;

#if TRACE > 1
  char buffer[IDSA_M_MESSAGE];
  int len;
#endif

  tree = tree_find(s->s_root, s->s_buffer[i]);
  if (tree == NULL) {		/* not found in root, return success rate of root */
    match = s->s_success;
    s->s_success *= s->s_decay_success;	/* not the failure */
  } else {			/* root matches, bump success rate */
    s->s_success = 1.0 + (s->s_success * s->s_decay_success);
    match = s->s_decay_match;
    prev = tree;
    i = 1;
    while (tree) {
#if TRACE > 1
      len = idsa_unit_print(s->s_buffer[i], buffer, IDSA_M_MESSAGE - 1, 0);
      buffer[len] = '\0';
      fprintf(stderr, "sequence_match(): looking for <%s:%d>\n", buffer, i);
#endif
      tree = tree_find(prev->t_root, s->s_buffer[i]);
      if (tree) {
	prev->t_success = 1.0 + (prev->t_success * s->s_decay_success);
	bubble_node(s, tree);	/* move node to front */
	match *= s->s_decay_match;
	prev = tree;
	i++;
      } else {
	match = match * (prev->t_success);
	prev->t_success *= s->s_decay_success;
      }
    }
  }

#if TRACE > 1
  fprintf(stderr, "sequence_match(): matches in %d positions, value %f\n", i, match);
#endif

  /* match = success[i] * decay_match^i */

  return match;
}

static void sequence_add(SEQUENCE * s)
{
  int i;
  TREE *tree, *back;

  /* WARNING: ensure that GC does not munch our own entry */

  back = tree_find(s->s_root, s->s_buffer[0]);
  if (back == NULL) {		/* completely foreign sequence, need to insert into root */
#if TRACE > 1
    fprintf(stderr, "sequence_add(): root not found, need to create\n");
#endif
    tree = grab_node(s, NULL, s->s_buffer[0]);
    s->s_root = tree_insert(s->s_root, tree);
#if TRACE > 1
    tree_check(s->s_root);
#endif
    return; /** bomb out **/
  }

  /* at least the first element matches */
#if TRACE > 1
  fprintf(stderr, "sequence_add(): matched %p[%d]\n", back, 0);
#endif
  tree = back;
  raise_node(s, back);
  i = 1;
  while (tree != NULL) {
    tree = tree_find(back->t_root, s->s_buffer[i]);
    if (tree) {
#if TRACE > 1
      fprintf(stderr, "sequence_add(): matched %p[%d]\n", tree, i);
#endif
      back = tree;
      raise_node(s, back);
      i++;
      if (i >= s->s_history) {
	return;	/** bomb out **/
      }
    }
  }

  tree = grab_node(s, back, s->s_buffer[i]);
#if TRACE > 1
  fprintf(stderr, "sequence_add(): adding new %p[%d] to %p\n", tree, i, back);
#endif
  back->t_root = tree_insert(back->t_root, tree);
#if TRACE > 1
  tree_check(back->t_root);
#endif
  tree->t_back = back;

}

static int sequence_do(SEQUENCE * s, IDSA_UNIT * u)
{
  double match, deviation, delta, average;
  int result;

  shift_history(s, u);		/* add new event to history */

#ifdef TRACE
  fprintf(stderr, "sequence_do(): -- dumping history --\n");
  dump_history(s, stderr);
  fprintf(stderr, "sequence_do(): -- dumping sequences --\n");
  fprintf(stderr, "[0x0000000]*:%f\n", s->s_success);
  dump_sequence(s->s_root, stderr);
  fprintf(stderr, "sequence_do(): ----- end of dump -----\n");
#endif

  match = sequence_match(s);	/* see how odd this one is */

  deviation = sqrt(s->s_variance * s->s_fudge);
  average = s->s_average * s->s_fudge;


#ifdef TRACE
  fprintf(stderr, "sequence_do(): running: average=%f, variance=%f\n", s->s_average, s->s_variance);
  fprintf(stderr, "sequence_do(): normalised: match=%f, average=%f, deviation=%f\n", match, average, deviation);
#endif

  if (match > (average + deviation * s->s_deviations)) {	/* above some std deviation multiple */
#ifdef TRACE
    fprintf(stderr, "sequence_do(): anomaly\n\n");
#endif
    result = 1;
  } else {			/* below threshold, event ok */
#ifdef TRACE
    fprintf(stderr, "sequence_do(): normal\n\n");
#endif
    result = 0;
  }

  sequence_add(s);		/* no match, needs insert */

  s->s_average = match + (s->s_average * s->s_decay_average);
  delta = average - match;
  s->s_variance = (delta * delta) + (s->s_variance * s->s_decay_average);

  return result;
}

/****************************************************************************/

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

static SEQUENCE *find_root(SEQUENCE * seq, char *name)
{
  while (seq) {
    if (strcmp(name, seq->s_name)) {
      seq = seq->s_next;
    } else {
      return seq;
    }
  }

  return NULL;
}

/****************************************************************************/

static void *sad_global_start(IDSA_RULE_CHAIN * c)
{
  SEQUENCE **root;

  root = malloc(sizeof(SEQUENCE *));
  if (root == NULL) {
    idsa_chain_error_malloc(c, sizeof(SEQUENCE *));
    return NULL;
  }

  *root = NULL;

  return root;
}

static void sad_global_stop(IDSA_RULE_CHAIN * c, void *g)
{
  SEQUENCE **pointer, *alpha, *beta;

  pointer = g;

  if (pointer) {
    alpha = *pointer;
    while (alpha) {
      beta = alpha;
      alpha = alpha->s_next;
      sequence_free(beta);
    }
    free(pointer);
  }
}

/****************************************************************************/

static void *sad_test_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  IDSA_MEX_TOKEN *variable, *name, *type, *token, *count, *hist, *dev, *decay;
  unsigned int typeval;
  int countval, histval, devval, decayval;
  VARIABLE *handle;
  SEQUENCE *sequence, **pointer;

  pointer = g;

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

  decayval = DEFAULT_DECAY;
  devval = DEFAULT_DEVIATION;
  histval = DEFAULT_HISTORY;
  countval = DEFAULT_COUNT;

  count = NULL;
  hist = NULL;
  dev = NULL;
  decay = NULL;

  token = idsa_mex_get(m);
  while (token && (token->t_id == IDSA_PARSE_COMMA)) {
    token = idsa_mex_get(m);
    if (token) {
      if (!strcmp("decay", token->t_buf)) {
	decay = idsa_mex_get(m);
	if (decay == NULL) {
	  idsa_chain_error_mex(c, m);
	  return NULL;
	}
	decayval = atof(decay->t_buf);
	if ((decayval > 1.0) || (decayval < 0.0)) {
	  idsa_chain_error_usage(c, "variable \"%s\" on line %d needs a decay factor in range 0 to 1", token->t_buf, token->t_line);
	  return NULL;
	}
      } else if (!strcmp("deviations", token->t_buf)) {
	dev = idsa_mex_get(m);
	if (dev == NULL) {
	  idsa_chain_error_mex(c, m);
	  return NULL;
	}
	devval = atof(dev->t_buf);
	if (devval < 0.0) {
	  idsa_chain_error_usage(c, "variable \"%s\" on line %d needs a deviation value greater than 0", token->t_buf, token->t_line);
	  return NULL;
	}
      } else if (!strcmp("history", token->t_buf)) {
	hist = idsa_mex_get(m);
	if (hist == NULL) {
	  idsa_chain_error_mex(c, m);
	  return NULL;
	}
	histval = atoi(hist->t_buf);
	if (histval < 3) {
	  idsa_chain_error_usage(c, "variable \"%s\" on line %d needs a history larger than 2", token->t_buf, token->t_line);
	  return NULL;
	}
      } else if (!strcmp("count", token->t_buf)) {
	count = idsa_mex_get(m);
	if (count == NULL) {
	  idsa_chain_error_mex(c, m);
	  return NULL;
	}
	countval = atoi(count->t_buf);
	if (countval < 6) {
	  idsa_chain_error_usage(c, "variable \"%s\" on line %d needs an element count greater than 6", token->t_buf, token->t_line);
	  return NULL;
	}
      } else {
	idsa_chain_error_usage(c, "unknown option \"%s\" for sad module on line %d", token->t_buf, token->t_line);
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
  fprintf(stderr, "sad_test_start(): variable=%s, field name=%s\n", variable->t_buf, name->t_buf);
#endif

  if (countval * 2 < histval) {
    if (count) {
      idsa_chain_error_usage(c, "variable \"%s\" on line %d needs an element count greater than twice its history", token->t_buf, token->t_line);
      return NULL;
    } else {
      countval = histval * histval;
    }
  }

  sequence = find_root(*pointer, variable->t_buf);
  if (sequence) {		/* sequence already exists */
    if (typeval != sequence->s_type) {
      idsa_chain_error_usage(c, "conflicting types for variable \"%s\" on line %d", variable->t_buf, variable->t_line);
      return NULL;
    }

    if ((hist && (histval != sequence->s_history))
	|| (count && (countval != sequence->s_count))
	|| (dev && (devval != sequence->s_deviations))
	|| (decay && (decayval != sequence->s_decay_average))
	) {
      idsa_chain_error_usage(c, "conflicting options for variable \"%s\" on line %d", variable->t_buf, variable->t_line);
      return NULL;
    }
  } else {			/* need to allocate a new sequence */
    sequence = sequence_new(variable->t_buf, typeval, countval, histval, decayval, devval);
    if (sequence == NULL) {
      idsa_chain_error_malloc(c, sizeof(SEQUENCE) + countval * (sizeof(TREE) + sizeof(IDSA_UNIT)));
      return NULL;
    }
    sequence->s_next = *pointer;
    *pointer = sequence;
  }

  handle = malloc(sizeof(VARIABLE));	/* fill in handle */
  if (handle == NULL) {
    idsa_chain_error_malloc(c, sizeof(VARIABLE));
    return NULL;
  }
  strncpy(handle->v_name, name->t_buf, IDSA_M_NAME - 1);
  handle->v_name[IDSA_M_NAME - 1] = '\0';
  handle->v_number = idsa_resolve_request(idsa_resolve_code(handle->v_name));
  handle->v_sequence = sequence;

#ifdef TRACE
  fprintf(stderr, "sad_test_start(): got handle <%s:%d>\n", handle->v_name, handle->v_number);
#endif

  return handle;
}

/****************************************************************************/
/* Does       : The actual work of testing an event                         */

static int sad_test_do(IDSA_RULE_CHAIN * c, void *g, void *t, IDSA_EVENT * q)
{
  SEQUENCE *sequence;
  VARIABLE *variable;
  IDSA_UNIT *unit;

  variable = t;
  sequence = variable->v_sequence;
  if (variable->v_number < idsa_request_count()) {
    unit = idsa_event_unitbynumber(q, variable->v_number);
  } else {
    unit = idsa_event_unitbyname(q, variable->v_name);
  }
  if (unit == NULL) {
#ifdef TRACE
    fprintf(stderr, "sad_test_do(): unable to get hold of unit\n");
#endif
    return 0;
  }
  return sequence_do(sequence, unit);
}

/****************************************************************************/
/* Notes      : Pretend that all are different, gets sorted out in start    */

static int sad_test_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *t)
{
  return 1;
}

/****************************************************************************/
/* Does       : Nothing, deletion happens in gstop                          */

static void sad_test_stop(IDSA_RULE_CHAIN * c, void *g, void *t)
{
  VARIABLE *variable;

  variable = t;
  if (variable) {
    variable->v_sequence = NULL;
    free(variable);
  }
}

/****************************************************************************/
/* Does       : Registers a new module. Usually this function is the same   */
/*              across modules, except for name changes                     */
/* Returns    : Pointer to module structure, or NULL on failure             */

IDSA_MODULE *idsa_module_load_sad(IDSA_RULE_CHAIN * c)
{
  IDSA_MODULE *result;

  result = idsa_module_new(c, "sad");
  if (result) {
    result->global_start = &sad_global_start;
    result->global_stop = &sad_global_stop;

    result->test_start = &sad_test_start;
    result->test_cache = &sad_test_cache;
    result->test_do = &sad_test_do;
    result->test_stop = &sad_test_stop;
  }

  return result;
}
