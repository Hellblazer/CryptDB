#include "AvlTree.h"
#include <iostream>

#include "NTL/ZZ.h"

using namespace std;
using namespace NTL;

/**
 * Construct the tree.
 */
template <class T, typename Compare, typename Distance>
AvlTree<T,Compare, Distance>::AvlTree() throw (NotFound):
  root(NULL),_sanity(false)
{
}

/**
 * Copy constructor.
 */
template <class T, typename Compare, typename Distance>
AvlTree<T,Compare, Distance>::AvlTree( const AvlTree<T,Compare, Distance> & rhs ) :
  root( NULL )
{
	*this = rhs;
}

/**
 * Destructor for the tree.
 */
template <class T, typename Compare, typename Distance>
AvlTree<T,Compare, Distance>::~AvlTree( )
{
	makeEmpty( );
}

/**
 * Insert x into the tree; duplicates are ignored.
 *
 * Takes O(log n) time.
 */
template <class T, typename Compare, typename Distance>
bool AvlTree<T,Compare, Distance>::insert( const T & x )
{
	bool retVal = insert( x, root );

	// Perform a sanity check since the structure has been altered
	//
	if ( retVal && get_sanity() ) { sanityCheck(); }


	// Whether the node was successfully inserted or not (i.e. wasn't a duplicate)
	//
	return retVal;
}

/**
 * Remove x from the tree. Nothing is done if x is not found.
 *
 * If x is found, the complexity is O(n) as the entire tree needs
 * to be rebalanced.
 */
template <class T, typename Compare, typename Distance>
bool AvlTree<T,Compare, Distance>::remove( const T & x )
{
	// First find the node in the tree
	//
	AvlNode<T,Compare, Distance>* currNode = find(x, root);

	// Only do this when the current node is valid
	//
	if ( currNode )
	{
		// See if it's a leaf
		//
		if ( currNode->isLeaf() )
		{
			// If we're a leaf and we have no parent, then the tree
			// will be emptied
			//
			if ( !currNode->parent )
			{
				root = NULL;
			}

			// If it's a leaf node, simply remove it
			//
			removeNode(currNode);
			delete currNode;
		}
		else
		{
			// Get the parent object
			//
			AvlNode<T,Compare, Distance>* parentNode = currNode->parent;
	
			// Remove the child and reconnect the smallest node in the right sub tree
			// (in order successor)
			//
			AvlNode<T,Compare, Distance>* replaceNode = findMin(currNode->right);

			// See if there's even a right-most node
			//
			if ( !replaceNode )
			{
				// Get the largest node on the left (because the right doesn't exist)
				//
				replaceNode = findMax(currNode->left);
			}

			// Disconnect the replacement node's branch
			//
			removeNode(replaceNode);

			// Disconnect the current node
			//
			removeNode(currNode);

			// Get the current node's left and right branches
			//
			AvlNode<T,Compare,Distance>* left = currNode->left;
			AvlNode<T,Compare,Distance>* right = currNode->right;

			// We no longer need this node
			//
			delete currNode;

			// Check to see if we removed the root node
			//
			if ( !parentNode )
			{
				// Merge the branches into the parent node of what we
				// deleted
				//
				merge(replaceNode, parentNode);
				merge(left, parentNode);
				merge(right, parentNode);

				// Now we're the the root
				//
				root = parentNode;
			}
			else
			{
				// Merge the branches into the parent node of what we
				// deleted, we let the merge algorithm decide where to
				// put the branches
				//
				merge(replaceNode, parentNode);
				merge(left, parentNode);
				merge(right, parentNode);
			}
		}

		// Balance the tree
		//
		balanceTree();

		// Perform a sanity check since the structure has been altered
		//
		if ( get_sanity() ) { sanityCheck(); }

		// The node was found and removed successfully
		//
		return true;
	}
	else
	{
		// Perform a sanity check since the structure has been altered
		//
		if ( get_sanity() ) { sanityCheck(); }

		// The node was not found
		//
		return false;
	}
}

/**
 * Find the smallest item in the tree. Return smallest item or throws NotFound if empty.
 *
 * Takes O(log n) time.
 */
template <class T, typename Compare, typename Distance>
const T & AvlTree<T,Compare, Distance>::findMin( ) const throw (NotFound)
{
	return elementAt( findMin( root ) );
}

/**
 * Find the largest item in the tree. Returns the largest item or throws NotFound if empty.
 *
 * Takes O(log n) time.
 */
template <class T, typename Compare, typename Distance>
const T & AvlTree<T,Compare, Distance>::findMax( ) const throw (NotFound)
{
	return elementAt( findMax( root ) );
}

/**
 * Find the middle element this is the same as the root in a balanced tree
 */
template <class T, typename Compare, typename Distance>
const T & AvlTree<T,Compare, Distance>::rootElement() const throw (NotFound)
{
	return elementAt( root );
}

/**
 * Find the middle element this is the same as the root in a balanced tree
 */
template <class T, typename Compare, typename Distance>
const T * const AvlTree<T,Compare, Distance>::rootElementPtr() const
{
	return elementPtrAt( root );
}

/**
 * Find the previous sequential item in the tree.
 */
template <class T, typename Compare, typename Distance>
const T & AvlTree<T,Compare, Distance>::prevElement( const T& x ) const throw (NotFound)
{
	return elementAt( prev( x ) );
}

/**
 * Find the next sequential item in the tree.
 */
template <class T, typename Compare, typename Distance>
const T & AvlTree<T,Compare, Distance>::nextElement( const T& x ) const throw (NotFound)
{
	return elementAt( next( x ) );
}

/**
 * Find the previous sequential item in the tree.
 */
template <class T, typename Compare, typename Distance>
const T * const AvlTree<T,Compare, Distance>::prevElementPtr( const T& x ) const
{
	return elementPtrAt( prev( x ) );
}

/**
 * Find the next sequential item in the tree.
 */
template <class T, typename Compare, typename Distance>
const T * const AvlTree<T,Compare, Distance>::nextElementPtr( const T& x ) const
{
	return elementPtrAt( next( x ) );
}

/**
 * Find item x in the tree. Returns the matching item or NULL if not found.
 *
 * Takes O(log n) time.
 */
template <class T, typename Compare, typename Distance>
AvlNode<T,Compare, Distance> * AvlTree<T,Compare, Distance>::find( const T & x ) const
{
	return find(x, root);
}

template <class T, typename Compare, typename Distance>
T& AvlTree<T,Compare, Distance>::find( const T & x ) throw (NotFound)
{
	AvlNode<T,Compare,Distance>* node = find(x, root);
	if ( node )
	{
		return node->element;
	}
	else
	{
		throw NotFound();
	}
}

/**
 * Find the closest item in the tree to x (requires distance).
 * Return the matching item or NULL if not found.
 */
template <class T, typename Compare, typename Distance>
AvlNode<T,Compare, Distance> * AvlTree<T,Compare, Distance>::findClosest( const T & x ) const
{
	return findClosest(x, root);
}

/**
 * Gets the element to the left of x, or NULL if not found
 *
 * Takes O(1) time.
 */
template <class T, typename Compare, typename Distance>
const T * const AvlTree<T,Compare,Distance>::leftElementPtr( const T & x) const
{
	AvlNode<T, Compare, Distance>* retVal = find(x);
	if ( retVal ) { return elementPtrAt(retVal->left); }
	else
	{
		return NULL;
	}
}

/**
 * Gets the element to the right of x, or NULL if not found
 *
 * Takes O(1) time.
 */
template <class T, typename Compare, typename Distance>
const T * const AvlTree<T,Compare,Distance>::rightElementPtr( const T & x) const
{
	AvlNode<T, Compare, Distance>* retVal = find(x);
	if ( retVal ) { return elementPtrAt(retVal->right); }
	else
	{
		return NULL;
	}
}

/**
 * Return the element immediately to the left of a given item x that may not
 * necessarily be in the tree
 */
template <class T, typename Compare, typename Distance>
const T* const AvlTree<T, Compare, Distance>::closestLeftOf(const T& x) const
{
	AvlNode<T, Compare, Distance>* retVal = findClosest(x);

	// See if the closer element is to the left of
	// the given item
	//
	if ( retVal && !_compare(elementAt(retVal), x) )
	{
		// The closest element is to the right of x, so we
		// need to return the element that is immediately
		// to its left
		//
		return prevElementPtr( elementAt(retVal) );
	}
	else
	{
		// Either not found, or the closest element is to the left
		// of or equal to x
		//
		return elementPtrAt(retVal);
	}
}

/**
 * Return the element immediately to the right of a given item x that may not
 * necessarily be in the tree.
 *
 * Takes O(log n) time.
 */
template <class T, typename Compare, typename Distance>
const T* const AvlTree<T, Compare, Distance>::closestRightOf(const T& x) const
{
	AvlNode<T, Compare, Distance>* retVal = findClosest(x);

	// See if the closer element is actually to the right of
	// the given item
	//
	if ( retVal && _compare(elementAt(retVal), x) )
	{
		// The closest element is to the left of x, so we
		// need to return the element that is immediately
		// to its right
		//
		return nextElementPtr( elementAt(retVal) );
	}
	else
	{
		// Either not found, or the closest element is to the right
		// of or equal to x
		//
		return elementPtrAt(retVal);
	}
}

/**
 * Find the previous sequential item in the tree in O(log n) time.
 */
template <class T, typename Compare, typename Distance>
AvlNode<T,Compare, Distance> * AvlTree<T,Compare, Distance>::prev( const T & x ) const
{
	return prev(find(x));
}

/**
 * Find the next sequential item in the tree in O(log n) time.
 */
template <class T, typename Compare, typename Distance>
AvlNode<T,Compare, Distance> * AvlTree<T,Compare, Distance>::next( const T & x ) const
{
	return next(find(x));
}

/**
 * Find the previous sequential item in the tree
 *
 * Takes O(log n) time.
 */
template <class T, typename Compare, typename Distance>
AvlNode<T,Compare, Distance> * AvlTree<T,Compare, Distance>::prev( AvlNode<T,Compare, Distance>* t ) const
{
	if ( t )
	{
		// We have a valid node in the tree, first check its left branch
		//
		if ( t->left )
		{
			// The branch on the left is sequentially previous to this item
			//
			return t->left;
		}
		else if ( t->parent )
		{
			// Now check to see if we're the left node on our parent
			//
			if ( t->isLeft() )
			{
				// We're on the left side of our parent, which means the parent
				// is greater than us. So we need to find our parent's sequential
				// previous element.
				//
				// We disconnect ourselves momentarily to allow this operation to
				// ignore this branch
				//
				t->parent->setLeft(NULL);
				AvlNode<T, Compare, Distance>* parentsPrev = prev(t->parent);

				// Reconnect ourselves back to the tree
				//
				t->parent->setLeft(t);

				return parentsPrev;
			}
			else
			{
				// We're on the right side of our parent and we don't have a left
				// child, this must mean that our parent is the previous sequential
				// element in the tree.
				//
				// If we're the root node, then the parent is naturally NULL so the
				// return value is correct.
				//
				return t->parent;
			}
		}
		else
		{
			// We're the root node and have no left child
			//
			return NULL;
		}
	}
	else
	{
		// Not a valid node
		//
		return NULL;
	}
}

/**
 * Find the next sequential item in the tree
 *
 * Takes O(log n) time.
 */
template <class T, typename Compare, typename Distance>
AvlNode<T,Compare, Distance> * AvlTree<T,Compare, Distance>::next( AvlNode<T,Compare, Distance>* t ) const
{
	if ( t )
	{
		// We have a valid node in the tree, first check its right branch
		//
		if ( t->right )
		{
			// The branch on the right is sequentially next to this item
			//
			return t->right;
		}
		else if ( t->parent )
		{
			// Now check to see if we're the left node on our parent
			//
			if ( t->isLeft() )
			{
				// We're on the right side of our parent and we don't have a right
				// child, this must mean that our parent is the next sequential
				// element in the tree.
				//
				// If we're the root node, then the parent is naturally NULL so the
				// return value is correct.
				//
				return t->parent;
			}
			else
			{
				// We're on the right side of our parent, which means the parent
				// is less than us. So we need to find our parent's sequential
				// next element
				//
				// We disconnect ourselves momentarily to exclude this part
				// of the tree from the search
				//
				t->parent->setRight(NULL);
				AvlNode<T, Compare, Distance>* parentsNext = next(t->parent);

				// Reconnect the tree back
				//
				t->parent->setRight(t);

				return parentsNext;
			}
		}
		else
		{
			// We're the root node and have no right child
			//
			return NULL;
		}
	}
	else
	{
		// Not a valid node
		//
		return NULL;
	}
}

/**
 * Make the tree logically empty.
 */
template <class T, typename Compare, typename Distance>
void AvlTree<T,Compare, Distance>::makeEmpty( )
{
	makeEmpty( root );
}

/**
 * Test if the tree is logically empty. Return true if empty, false otherwise.
 *
 * Takes O(1) time.
 */
template <class T, typename Compare, typename Distance>
bool AvlTree<T,Compare, Distance>::isEmpty( ) const
{
	return root == NULL;
}

/**
 * Print the tree contents in sorted order.
 *
 * Takes O(n log n) time.
 */
template <class T, typename Compare, typename Distance>
void AvlTree<T,Compare, Distance>::printTree( ostream& out ) const
{
	if( isEmpty( ) )
	{
		out << "Empty tree" << endl;
	}
	else
	{
		printTree( out, root );
	}
}

/**
 * Get the height of the tree
 *
 * Takes O(log n) time.
 */
template <class T, typename Compare, typename Distance>
int AvlTree<T,Compare, Distance>::height() const
{
	return root->height();
}

/**
 * Deep copy.
 *
 * Takes O(n) time.
 */
template <class T, typename Compare, typename Distance>
const AvlTree<T,Compare, Distance> &
AvlTree<T,Compare, Distance>::
operator=( const AvlTree<T,Compare, Distance> & rhs )
{
	// Don't clone if it's the same pointer
	//
	if ( this != &rhs )
	{
		makeEmpty( );

		root = clone( rhs.root );
	}

	return *this;
}

/**
 * Internal method to get element field in node t.
 * Return the element field or ITEM_NOT_FOUND if t is NULL.
 *
 * Takes O(1) time.
 */
template <class T, typename Compare, typename Distance>
const T & AvlTree<T,Compare, Distance>::elementAt( const AvlNode<T,Compare, Distance> *t ) const throw (NotFound)
{
	if( t == NULL )
	   throw NotFound();
	else
	   return t->element;
}

/**
 * Internal method to get element field pointer in node t.
 * Return the element field or NULL if t is NULL.
 *
 * Takes O(1) time.
 */
template <class T, typename Compare, typename Distance>
const T * const AvlTree<T,Compare, Distance>::elementPtrAt( const AvlNode<T,Compare, Distance> *t ) const
{
	if( t == NULL )
	   return NULL;
	else
	   return &(t->element);
}

/**
 * Internal method to insert into a subtree.
 * x is the item to insert.
 * t is the node that roots the tree.
 *
 * Takes O(log n) time.
 */
template <class T, typename Compare, typename Distance>
bool AvlTree<T,Compare, Distance>::insert( const T & x, AvlNode<T,Compare, Distance> * & t )
{
	if ( t == NULL )
	{
		t = new AvlNode<T,Compare, Distance>( x, NULL, NULL, NULL );

		// An empty sub-tree here, insertion successful
		//
		return true;
	}
	else if ( _compare(x, t->element) )
	{
		// O(log n)
		//
		bool retVal = insert( x, t->left );

		if ( retVal )
		{
			// O(1)
			//
			t->left->setParent(t);
	
			// O(1)
			//
			if( t->balanceFactor() < -1 )
			{
				// See if it went left of the left
				//
				if( _compare(x, t->left->element) )
				{
					rotateWithLeftChild( t );
				}
				else
				{
					// The element goes on the right of the left
					//
					doubleWithLeftChild( t );
				}
			}
		}

		return retVal;
	}
	else if ( _compare(t->element, x) )
	{
		bool retVal = insert( x, t->right );

		// Only do this if the insertion was successful
		//
		if ( retVal )
		{
			t->right->setParent(t);
	
			if ( t->balanceFactor() > 1 )
			{
				// See if it went right of the right
				//
				if( _compare(t->right->element, x) )
				{
					rotateWithRightChild( t );
				}
				else
				{
					// The element goes on the left of the right
					//
					doubleWithRightChild( t );
				}
			}
		}

		return retVal;
	}
	else
	{
		return false;  // Duplicate
	}
}

/**
 * Merge a different tree with ours in O(n) time.
 *
 * The complexity is linear due to the need to rebalance the tree. We could take
 * another approach and indivdually insert each item in the tree which would take
 * O(n) time also.
 */
template <class T, typename Compare, typename Distance>
bool AvlTree<T,Compare, Distance>::merge( const AvlTree<T,Compare,Distance>& b )
{
	AvlNode<T,Compare,Distance>* c = b->clone();
	bool retVal = merge(c->root, root);

	// Re-balance the tree if the merge was successful
	//
	if ( retVal )
	{
		balanceTree();
	}
	else
	{
		delete c;
	}

	return retVal;
}

/**
 * Merge a tree with ours, if successful, we take over responsibility for the tree passed to us
 *
 * This method is internal ONLY because it can leave the tree potentially unbalanced. The only
 * places it is used is in merging another tree with ours (above) and during removal of a node.
 *
 * In both cases, a rebalance is performed on the entire tree
 */
template <class T, typename Compare, typename Distance>
bool AvlTree<T,Compare, Distance>::merge( AvlNode<T,Compare,Distance>* b, AvlNode<T,Compare, Distance> * & t )
{
	if ( !b )
	{
		return false;
	}
	else
	{
		bool retVal = false;

		if ( t == NULL )
		{
			// Set this element to that subtree
			//
			t = b;

			// The parent here should be NULL anyway, but we
			// set it just to be sure. This pointer will be
			// used as a flag to indicate where in the call
			// stack the tree was actually set.
			//
			// The middle layers of this method's call will
			// all have their parent references in tact since
			// no operations took place there.
			//
			//t->parent = NULL;
			t->setParent(NULL);
	
			// We were successful in merging
			//
			retVal = true;
		}
		else if ( _compare(b->element, t->element) )
		{
			retVal = merge( b, t->left );
	
			// Only do this if the insertion actually took place
			//
			if ( retVal && !t->left->parent )
			{
				t->left->setParent(t);
			}
		}
		else if ( _compare(t->element, b->element) )
		{
			retVal = merge( b, t->right );
	
			// Only do this if the insertion was successful
			//
			if ( retVal && !t->right->parent )
			{
				t->right->setParent(t);
			}
	
			return retVal;
		}
	
		return retVal;
	}
}

/**
 * Balance the tree, takes O(n) time
 */
template <class T, typename Compare, typename Distance>
void AvlTree<T,Compare, Distance>::balanceTree(AvlNode<T,Compare, Distance>* &node)
{
	if ( node )
	{
		// First see what the balance factor for this node is
		//
		int balFactor = node->balanceFactor();
	
		if ( balFactor < -1 )
		{
			// See if we're heavy left of the left
			//
			if(  node->left->balanceFactor() < 0 )
			{
				rotateWithLeftChild( node );
			}
			else // if (node->left->balanceFactor() > 0 )
			{
				// We're heavy on the right of the left
				//
				doubleWithLeftChild( node );
			}
		}
		else if ( balFactor > 1 )
		{
			// See if it we're heavy right of the right
			//
			if( node->right->balanceFactor() > 0 )
			{
				rotateWithRightChild( node );
			}
			else // if ( node->right->balanceFactor() < 0 )
			{
				// The element goes on the left of the right
				//
				doubleWithRightChild( node );
			}
		}
		else // if ( balFactor >= -1 && balFactor <= 1)
		{
			// We're balanced here, but are our children balanced?
			//
			balanceTree(node->left);
			balanceTree(node->right);
		}
	}
}

/**
 * Internal method to find the smallest item in a subtree t.
 * Return node containing the smallest item.
 *
 * Takes O(log n) time.
 */
template <class T, typename Compare, typename Distance>
AvlNode<T,Compare, Distance> *
AvlTree<T,Compare, Distance>::findMin( AvlNode<T,Compare, Distance> *t ) const
{
	if( t == NULL)
	{
		return t;
	}

	while( t->left != NULL )
	{
		t = t->left;
	}

	return t;
}

/**
 * Internal method to find the largest item in a subtree t.
 * Return node containing the largest item.
 *
 * Takes O(log n) time.
 */
template <class T, typename Compare, typename Distance>
AvlNode<T,Compare, Distance> *
AvlTree<T,Compare, Distance>::findMax( AvlNode<T,Compare, Distance> *t ) const
{
	if( t == NULL )
	{
		return t;
	}

	while( t->right != NULL )
	{
		t = t->right;
	}

	return t;
}

/**
 * Internal method to find an item in a subtree.
 * x is item to search for.
 * t is the node that roots the tree.
 * Return node containing the matched item.
 *
 * Takes O(log n) time.
 */
template <class T, typename Compare, typename Distance>
AvlNode<T,Compare, Distance> *
AvlTree<T,Compare, Distance>::find( const T & x, AvlNode<T,Compare, Distance> *t ) const
{
	while( t != NULL )
	{
		if ( _compare(x, t->element) )
		{
			t = t->left;
		}
		else if ( _compare(t->element, x) )
		{
			t = t->right;
		}
		else
		{
			return t;	// Match
		}
	}

	return NULL;   // No match
}

/**
 * Find the closest match to an item, this requires a distance
 * calculator to compare whether a given item is closer or
 * farther. Consider the following example:
 *
 *               5
 *              / \
 *             1  20
 *
 * findClosest(6) in this case would have to return 5 and not 20.
 *
 * In cases where the two nodes are equidistant, there is an actual
 * match
 *
 * Takes O(log n) time.
 */
template <class T, typename Compare, typename Distance>
AvlNode<T,Compare, Distance> *
AvlTree<T,Compare, Distance>::findClosest( const T & x, AvlNode<T,Compare, Distance> *t ) const
{
	// Save the parent 
	//
	//AvlNode<T, Compare, Distance>* retVal = NULL;
	ZZ parentDistance = T.MAX;

	while( t != NULL )
	{
		// Do we have to go forward or back to get to x from this element
		//
		ZZ leftDistance = T.MAX;
		ZZ rightDistance = T.MAX;

		if ( t->left ) { leftDistance = _distance(t->left->element, x); }
		if ( t->right ) { rightDistance = _distance(t->right->element, x); }

		if ( fabs(parentDistance) < fabs(leftDistance) && fabs(parentDistance) < fabs(rightDistance) )
		{
			// The parent is the closest, we no longer have to check
			// more child nodes because we're getting farther away from
			// this node as we move down the tree
			//
			return t;
		}
		else
		{
			if ( fabs(leftDistance) < fabs(rightDistance) )
			{
				// The left side is closer
				//
				parentDistance = leftDistance;
				t = t->left;
			}
			else if ( fabs(rightDistance) < fabs(leftDistance) )
			{
				// The right side is closer
				//
				parentDistance = rightDistance;
				t = t->right;
			}
			else
			{
				// Exact match
				//
				return t;
			}
		}
	}

	return NULL;   // No match
}

/**
 * Internal method to make subtree empty.
 *
 * Takes O(n) time.
 */
template <class T, typename Compare, typename Distance>
void AvlTree<T,Compare, Distance>::makeEmpty( AvlNode<T,Compare, Distance> * & t ) const
{
	if( t != NULL )
	{
		makeEmpty( t->left );
		makeEmpty( t->right );

		delete t;
	}
	t = NULL;
}

/**
 * Internal method to clone subtree.
 *
 * Takes O(n) time.
 */
template <class T, typename Compare, typename Distance>
AvlNode<T,Compare, Distance> *
AvlTree<T,Compare, Distance>::clone( const AvlNode<T,Compare, Distance> * t ) const
{
	if( t == NULL )
	{
		return NULL;
	}
	else
	{
		// Create a node with the left and right nodes and a parent set to NULL
		//
		AvlNode<T,Compare,Distance>* retVal = new AvlNode<T,Compare, Distance>( t->element, NULL, clone( t->left ), clone( t->right ) );

		// Now set our children's parent node reference
		//
		if ( retVal->left ) { retVal->left->setParent(retVal); }
		if ( retVal->right ) { retVal->right->setParent(retVal); }

		return retVal;
	}
}

/**
 * Return the height of node t or -1 if NULL.
 */
template <class T, typename Compare, typename Distance>
int AvlTree<T,Compare, Distance>::height( AvlNode<T,Compare, Distance> *t ) const
{
	return t == NULL ? -1 : t->height();
}

/**
 * Return maximum of lhs and rhs.
 *
 * Takes O(1) time.
 */
template <class T, typename Compare, typename Distance>
int AvlTree<T,Compare, Distance>::max( int lhs, int rhs ) const
{
	return lhs > rhs ? lhs : rhs;
}

/**
 * Rotate binary tree node with left child.
 * For AVL trees, this is a single rotation for case 1.
 * Update heights, then set new root.
 *
 * Takes O(1) time.
 */
template <class T, typename Compare, typename Distance>
void AvlTree<T,Compare, Distance>::rotateWithLeftChild( AvlNode<T,Compare, Distance> * & k2 ) const
{
	AvlNode<T,Compare, Distance> *k1 = k2->left;
	AvlNode<T,Compare, Distance> *k2Parent = k2->parent;

	k2->setLeft(k1->right);
	if ( k2->left ) { k2->left->setParent( k2 ); }

	k1->setRight(k2);
	if ( k1->right ) { k1->right->setParent( k1 ); }

	k2 = k1;
	k2->setParent( k2Parent );
}

/**
 * Rotate binary tree node with right child.
 * For AVL trees, this is a single rotation for case 4.
 * Update heights, then set new root.
 *
 * Takes O(1) time.
 */
template <class T, typename Compare, typename Distance>
void AvlTree<T,Compare, Distance>::rotateWithRightChild( AvlNode<T,Compare, Distance> * & k1 ) const
{
	AvlNode<T,Compare, Distance> *k2 = k1->right;
	AvlNode<T,Compare, Distance> *k1Parent = k1->parent;

	k1->setRight(k2->left);
	if ( k1->right) { k1->right->setParent(k1); }

	k2->setLeft(k1);
	if ( k2->left ) { k2->left->setParent(k2); }

	k1 = k2;
	k1->setParent(k1Parent);
}

/**
 * Double rotate binary tree node: first left child.
 * with its right child; then node k3 with new left child.
 * For AVL trees, this is a double rotation for case 2.
 * Update heights, then set new root.
 *
 * Takes O(1) time.
 */
template <class T, typename Compare, typename Distance>
void AvlTree<T,Compare, Distance>::doubleWithLeftChild( AvlNode<T,Compare, Distance> * & k3 ) const
{
	rotateWithRightChild( k3->left );
	rotateWithLeftChild( k3 );
}

/**
 * Double rotate binary tree node: first right child.
 * with its left child; then node k1 with new right child.
 * For AVL trees, this is a double rotation for case 3.
 * Update heights, then set new root.
 *
 * Takes O(1) time.
 */
template <class T, typename Compare, typename Distance>
void AvlTree<T,Compare, Distance>::doubleWithRightChild( AvlNode<T,Compare, Distance> * & k1 ) const
{
	rotateWithLeftChild( k1->right );
	rotateWithRightChild( k1 );
}

/**
 * Internal method to print a subtree in sorted order.
 * t points to the node that roots the tree.
 *
 * Takes O(n) time 
 */
template <class T, typename Compare, typename Distance>
void AvlTree<T,Compare, Distance>::printTree( ostream& out, AvlNode<T,Compare, Distance> *t, int numTabs, char lr ) const
{
	if( t != NULL )
	{
		for (int i =0; i < numTabs; i++ ) { out << "  "; } out << "|_" << lr << "__ ";
		out << t->element << " {h = " << t->height() << ", b = " << t->balanceFactor() << "} ";
		out << hex << t << " (p = " << t->parent << ")" << dec;
		out << endl;

		printTree( out, t->left, numTabs + 1, '<' );
		printTree( out, t->right, numTabs + 1, '>' );
	}
}

// Perform a sanity check on the tree to make sure the references are correct
//
// O(n log n)
//
template <class T, typename Compare, typename Distance>
bool AvlTree<T,Compare, Distance>::sanityCheck() const
{
	return sanityCheck( root );
}

template <class T, typename Compare, typename Distance>
bool AvlTree<T,Compare, Distance>::sanityCheck(AvlNode<T,Compare, Distance>* const &node) const
{
	if ( !node )
	{
		return true;
	}
	else
	{
		if ( node->isLeaf() && !node->parent )
		{
			// This is the only node in the tree
			//
			return true;
		}
		else
		{
			int balFactor = node->balanceFactor();

			// Test the balance factor
			//
			bool retVal = (balFactor >= -1 && balFactor <= 1);
			if ( !retVal ) { /* cout << "XXX: balFactor < -1 || balFactor > 1 (" << balFactor << ") of " << node->element; */ }

			// Make sure we have no circular references
			//
			retVal &= (node->left != node); if ( !retVal ) { /* cout << "XXX: node->left == node"; */ }
			retVal &= (node->right != node);if ( !retVal ) { /* cout << "XXX: node->right == node"; */ }
	
			// See if there's a left branch
			//
			if ( retVal && node->left )
			{
				retVal &= (node->left->parent == node);
				if ( !retVal ) { /* cout << "XXX: node->left->parent != node"; */ }

				retVal &= (_compare(node->left->element, node->element));
				if ( !retVal ) { /* cout << "XXX: !_compare(" << node->left->element << ", " << node->element << ")"; */ }

				retVal &= sanityCheck(node->left);
				if ( !retVal ) { /* cout << "XXX: !sanityCheck(node->left)"; */ }
			}
		
			// See if there's a right branch
			//
			if ( retVal && node->right )
			{
				retVal &= (node->right->parent == node);
				if ( !retVal ) { /* cout << "XXX: node->right->parent != node"; */ }

				retVal &= !(_compare(node->right->element, node->element));
				if ( !retVal ) { /* cout << "XXX: _compare(" << node->right->element << ", " << node->element << ")"; */ }

				retVal &= sanityCheck(node->right);
				if ( !retVal ) { /* cout << "XXX: !sanityCheck(node->right)"; */ }
			}
	
			if ( !retVal )
			{
				// cout << ": insanity at " << node->element << endl;
			}

			return retVal;
		}
	}
}

// Removes a node from its parents and children
//
// O(1)
//
template <class T, typename Compare, typename Distance>
void AvlTree<T,Compare, Distance>::removeNode(AvlNode<T,Compare, Distance>* &node)
{
	// It is a leaf, simply remove the item and disconnect the parent
	//
	if ( node->isLeft() )
	{
		node->parent->setLeft(NULL);
	}
	else // (node == node->parent->right)
	{
		if ( node->parent ) { node->parent->setRight(NULL); }
	}

	node->setParent( NULL );
}

// Swap out one node for another.
//
// Takes O(1) time.
//
template <class T, typename Compare, typename Distance>
void AvlTree<T,Compare, Distance>::replaceNode(AvlNode<T,Compare, Distance>* &node1, AvlNode<T,Compare, Distance>* &node2)
{
	// Save both parent references
	//
	AvlTree<T,Compare, Distance>* node1Parent = node1->parent;
	AvlTree<T,Compare, Distance>* node2Parent = node2->parent;

	// First move node2 into node1's place
	//
	if ( node1Parent )
	{
		if ( isLeft(node1) )
		{
			node1Parent->setLeft(node2);
		}
		else // node1 is on the right
		{
			node1Parent->setRight(node2);
		}
	}
	node2->setParent( node1Parent );

	// Now move node1 into node2's place
	//
	if ( node2Parent )
	{
		if ( isLeft(node2) )
		{
			node2Parent->setLeft(node1);
		}
		else // node2 is on the right
		{
			node2Parent->setRight(node1);
		}
	}
	node1->setParent(node2Parent);
}


// This method returns all elements in the tree and terminates
// the array with a "NULL" pointer.
//
// O(n)
//
template <class T, typename Compare, typename Distance>
void AvlTree<T,Compare, Distance>::getAllElements(vector<T*>& elements, bool copy) const
{
	return getAllElements(elements, root, copy);
}

template <class T, typename Compare, typename Distance>
void AvlTree<T,Compare, Distance>::getAllElements(vector<T*>& elements, AvlNode<T,Compare,Distance>* b, bool copy) const
{
	if ( b )
	{
		// Do all of the left elements
		//
		getAllElements(elements, b->left, copy);

		if ( copy )
		{
			elements.push_back( new T(elementAt(b)) );
		}
		else
		{
			elements.push_back( &(b->element) );
		}

		// Do all of the right elements
		//
		getAllElements(elements, b->right, copy);
	}
}

// Adds all ancestors to a given vector. Adds copies or the internal references depending on the flag
//
// O(log n)
//
template <class T, typename Compare, typename Distance>
void AvlTree<T,Compare, Distance>::getAllAncestors(vector<T*>& ancestors, const T& x, bool copy) const
{
	getAllAncestors(ancestors, find(x), copy);
}

// Return all ancestors
//
// O(log n)
//
template <class T, typename Compare, typename Distance>
void AvlTree<T,Compare, Distance>::getAllAncestors(vector<T*>& ancestors, AvlNode<T,Compare,Distance>* node, bool copy) const
{
	if ( node && node->parent )
	{
		if ( copy )
		{
			ancestors.push_back( new T(elementAt(node->parent)) );
		}
		else
		{
			ancestors.push_back( &(node->parent->element) );
		}

		// Get all of the parent's ancestors also
		//
		getAllAncestors(ancestors, node->parent, copy);
	}
}

// Do a range query on the tree and return all matching elements
//
// O(log n + k)
//
template <class T, typename Compare, typename Distance>
void AvlTree<T,Compare,Distance>::rangeQuery(vector<T*>& range, const T& min, const T& max, bool copy) const
{
	// Only do something if it makes sense
	//
	if ( min <= max )
	{
		rangeQuery(range, root, min, max, copy);
	}
}

// Perform a range query on this branch and its sub-branch
//
// k = number of matches
//
// O(log n + k)
//
template <class T, typename Compare, typename Distance>
void AvlTree<T,Compare,Distance>::rangeQuery(vector<T*>& range, AvlNode<T,Compare,Distance>* b, const T& min, const T& max, bool copy) const
{
	// Find the split node
	//
	// O(log n)
	//
	while (
		b &&
		(le(max, b->element) || gt(min, b->element))
		)
	{
		if ( le(max, b->element) )
		{
			b = b->left;
		}
		else
		{
			b = b->right;
		}
	}

	// See if we found a split node
	//
	if ( b )
	{
		// O(log n + k)
		//
		AvlNode<T,Compare,Distance>* currNode = b->left;
		while ( currNode )
		{
			if ( lt(min, currNode->element) )
			{
				getAllElements(range, currNode->right, copy);
				currNode = currNode->left;
			}
			else
			{
				currNode = currNode->right;
			}
		}

		// Test ourselves to see if we should go into the return value or not
		//
		// O(1)
		//
		if ( le(b->element, max) && ge(b->element, min) )
		{
			if ( copy )
			{
				range.push_back(new T(elementAt(b)));
			}
			else
			{
				range.push_back(&(b->element));
			}
		}

		// Symmetrically add the right node as well
		//
		currNode = b->right;
		while ( currNode )
		{
			if ( gt(max, currNode->element) )
			{
				getAllElements(range, currNode->left, copy);
				currNode = currNode->right;
			}
			else
			{
				currNode = currNode->left;
			}
		}
	}
}

// Do a range query on the tree and call a method on each matching element
//
// CB = The complexity of the callback
// k = Number of matches
//
// O(log n + CB * k)
//
template <class T, typename Compare, typename Distance>
void AvlTree<T,Compare,Distance>::rangeQuery(RangeQueryCallback cb, const T& min, const T& max, void* arg) const
{
	// Only do something if it makes sense
	//
	if ( min <= max && cb )
	{
		rangeQuery(cb, root, min, max, arg);
	}
}

// CB = The complexity of the callback
// k = Number of matches
//
// O(log n + CB * k)
//
template <class T, typename Compare, typename Distance>
void AvlTree<T,Compare,Distance>::rangeQuery(RangeQueryCallback cb, AvlNode<T,Compare,Distance>* b, const T& min, const T& max, void* arg) const
{
	// Find the split node
	//
	while (
		b &&
		(le(max, b->element) || gt(min, b->element))
		)
	{
		if ( le(max, b->element) )
		{
			b = b->left;
		}
		else
		{
			b = b->right;
		}
	}

	// See if we found a split node
	//
	if ( b )
	{
		AvlNode<T,Compare,Distance>* currNode = b->left;
		while ( currNode )
		{
			if ( lt(min, currNode->element) )
			{
				// Call the call back
				//
				if ( currNode->right ) { (*cb)( currNode->right->element, arg ); }
				currNode = currNode->left;
			}
			else
			{
				currNode = currNode->right;
			}
		}

		// Test ourselves to see if we should go into the tree or not
		//
		// O(1)
		//
		if ( le(b->element, max) && ge(b->element, min) )
		{
			// Call the call back
			//
			(*cb)( b->element, arg );
		}

		currNode = b->right;
		while ( currNode )
		{
			if ( gt(max, currNode->element) )
			{
				// Call the call back
				//
				if ( currNode->left ) { (*cb)( currNode->left->element, arg ); }
				currNode = currNode->right;
			}
			else
			{
				currNode = currNode->left;
			}
		}
	}
}

/********************************************************/
/*                   AvlNode                            */
/********************************************************/

// Determine if this node is a leaf node or not
//
// O(1)
//
template <class T, typename Compare, typename Distance>
bool AvlNode<T,Compare, Distance>::isLeft()
{
	// It is a leaf, simply remove the item and disconnect the parent
	//
	if ( parent && this == parent->left )
	{
		return true;
	}
	else
	{
		return false;
	}
}

// Set the parent
//
// O(1)
//
template <class T, typename Compare, typename Distance>
void AvlNode<T,Compare, Distance>::setParent(AvlNode<T,Compare, Distance>* p)
{
	// Set our new parent
	//
	parent = p;

	// If we have a valid parent, set its height
	//
	if ( parent )
	{
		// Set the parent's height to include this tree. If the parent
		// already has a tree that is taller than the one we're attaching
		// then the parent's height remains unchanged
		//
		int rightHeight = (parent->right ? parent->right->_height : 0);
		int leftHeight = (parent->left ? parent->left->_height : 0);

		// The height of the tallest branch + 1
		//
		parent->_height = max(rightHeight, leftHeight) + 1;

		// Also set the balance factor
		//
		parent->_balanceFactor = rightHeight - leftHeight;
	}
}

// Set the left branch
//
// O(1)
//
template <class T, typename Compare, typename Distance>
void AvlNode<T,Compare, Distance>::setLeft(AvlNode<T,Compare, Distance>* l)
{
	// Set our new left node
	//
	left = l;

	// Set the height and balance factor
	//
	int rightHeight = (right ? right->_height : 0);
	int leftHeight = (left ? left->_height : 0);

	_height = max(rightHeight, leftHeight) + 1;
	_balanceFactor = (right ? right->_height : 0) - (left ? left->_height : 0);
}

// Set the right branch
//
// O(1)
//
template <class T, typename Compare, typename Distance>
void AvlNode<T,Compare, Distance>::setRight(AvlNode<T,Compare, Distance>* r)
{
	// Set our new right node
	//
	right = r;

	// Set the height and balance factor
	//
	int rightHeight = (right ? right->_height : 0);
	int leftHeight = (left ? left->_height : 0);

	_height = max(rightHeight, leftHeight) + 1;
	_balanceFactor = (right ? right->_height : 0) - (left ? left->_height : 0);
}

// Resets the parent's heights
//
// O(log n)
//
template <class T, typename Compare, typename Distance>
void AvlNode<T,Compare,Distance>::calcHeights()
{
	// Calculate the height of ourselves
	//
	// O(1)
	//
	_height = max(left ? left->_height : 0, right ? right->_height : 0) + 1;

	// And our parent
	//
	// O(log n)
	//
	if ( parent ) { parent->calcHeights(); }
}

// The height of a node
//
// O(1)
//
template <class T, typename Compare, typename Distance>
int AvlNode<T,Compare, Distance>::height() const
{
	// The height is equal to the maximum of the right or left side's height plus 1
	//
	// This can be done very inefficiently as in O(n) with the following line:
	//
	// 	return max(left ? left->height() : 0, right ? right->height() : 0) + 1;
	//
	return _height;
}

// The balance factor of a node
//
// O(1)
//
template <class T, typename Compare, typename Distance>
int AvlNode<T,Compare, Distance>::balanceFactor() const
{
	// The weight of a node is equal to the difference between
	// the weight of the left subtree and the weight of the
	// right subtree
	//
	// O(n) version =>
	// 	return (right ? right->height() : 0) - (left ? left->height() : 0);
	//
	return _balanceFactor;
}


