#ifndef AVLTREE_H_
#define AVLTREE_H_

#include <iostream>
#include <vector>
#include <math.h>
#include <float.h>

using namespace std;

// Node not found exception
//
class NotFound {};

// Unimplemented stub used for distance
//
template <class T>
struct nil: public binary_function<T, T, int>
{
	double operator()(const T& a, const T& b) const
	{
		return 0;
	}
};

// Node and forward declaration because g++ does
// not understand nested classes.
template <class T, typename Compare, typename Distance> class AvlTree;

template <class T, typename Compare, typename Distance> class AvlNode
{
	public:
		// The default constructor
		//
		AvlNode( const T & theElement, AvlNode* p, AvlNode* lt, AvlNode* rt)
		  : element( theElement ), parent(p), left( lt ), right( rt ), _height(1), _balanceFactor(0)
		{ }

		// Determines whether a given node is on the left side of its parent
		//
		bool isLeft();

		// Whether this node is a leaf node or not
		//
		bool isLeaf() { return !left && !right; }

		// Set the parent pointer
		//
		void setParent(AvlNode<T,Compare,Distance>* parent);

		// Set the left pointer
		//
		void setLeft(AvlNode<T,Compare,Distance>* l);
		void setRight(AvlNode<T,Compare,Distance>* r);

		// Get a child node or NULL if none exists
		//
		AvlNode<T,Compare,Distance>* getAChild() { return left ? left : right; }

		// Get the height and balance factor
		//
		int height() const;
		int balanceFactor() const;

	private:
		T element;

		AvlNode   *parent;
		AvlNode   *left;
		AvlNode   *right;

		int _height;
		int _balanceFactor;

		// Calculates all of the heights for this node and its ancestors
		//
		void calcHeights();

		friend class AvlTree<T, Compare,Distance>;
};


// AvlTree class
//
// Author: Hamid Badiozamani
// badiozam sdsu.edu
//

template <class T, typename Compare = less<T>, typename Distance = nil<T> >
class AvlTree
{
	public:
		AvlTree() throw (NotFound);
		AvlTree(const AvlTree & rhs);
		~AvlTree();

		const T & findMin() const throw (NotFound);
		const T & findMax() const throw (NotFound);

		// These methods find the element immediately to the left (sequentially previous)
		// or right (sequentially next) of a given element.
		//
		const T & rootElement() const throw (NotFound);
		const T & prevElement( const T & x) const throw (NotFound);
		const T & nextElement( const T & x) const throw (NotFound);

		const T * const rootElementPtr() const;
		const T * const prevElementPtr( const T & x) const;
		const T * const nextElementPtr( const T & x) const;

		const T * const leftElementPtr( const T & x) const;
		const T * const rightElementPtr( const T & x) const;

		// The element that is the closest left or right neighbor of
		// a given type T which may not be part of the tree. This
		// requires a correctly defined distance functor
		//
		const T * const closestLeftOf( const T & x) const;
		const T * const closestRightOf( const T & x) const;

		bool isEmpty( ) const;
		void printTree(ostream& out = cout) const;

		void makeEmpty( );
		bool insert( const T & x );
		bool remove( const T & x );
		int height() const;

		// Merging two trees together
		//
		bool merge( const AvlTree<T,Compare,Distance>& b );

		// Setting one tree equal to another
		//
		const AvlTree & operator=( const AvlTree & rhs );

		// Checking the sanity of a tree
		//
		bool sanityCheck() const;

		// Whether to perform auto sanity checks or not
		//
		void set_sanity(bool s) { _sanity = s; }
		bool get_sanity() const { return _sanity; }

		// Returns an ordered array of elements, terminated with a NULL element.
		// The caller is responsible for deallocation of the array.
		//
		// If copy is set to true, then the caller is also responsible for all
		// containing elements as well
		//
		// Otherwise, only the array must be deallocated and not the pointers returned
		// inside it
		//
		void getAllElements(vector<T*>& elements, bool copy = true) const;

		// Returns all ancestors of a given element, terminated with a NULL element.
		// The caller is responsible for deallocation of the array and all
		// containing elements.
		//
		void getAllAncestors(vector<T*>& ancestors, const T& x, bool copy = true) const;

		// This function signature is used for callbacks when performing range queries
		//
		typedef void (*RangeQueryCallback)(T& element, void* arg);

		// Returns a range query for all of the elements that lie within the min
		// and max inclusive
		//
		void rangeQuery(vector<T*>& range, const T& min, const T& max, bool copy = true) const;

		// A range query that calls a callback method on each match
		//
		void rangeQuery(RangeQueryCallback cb, const T& min, const T& max, void* arg) const;

		// Range query that returns another tree
		//
		//void rangeQuery(AvlTree<T,Compare,Distance>& range, const T& min, const T& max) const;

		// Returns the reference to an object in the tree that is equivalent
		// to the object passed in as parameter x.
		//
		// Useful because the reference returned can be manipulated, though
		// NOT in a way as to change its position relative to other elements
		//
		T& find(const T& x) throw (NotFound);

	private:
		// A reference to the root node
		//
		AvlNode<T,Compare,Distance> *root;

		// Find a node in the tree
		//
		AvlNode<T,Compare,Distance> * find( const T & x) const;

		// Find the closest node in the tree to the given element
		//
		AvlNode<T,Compare,Distance> * findClosest( const T & x) const;

		const T & elementAt( const AvlNode<T,Compare,Distance> *t ) const throw (NotFound);
		const T * const elementPtrAt( const AvlNode<T,Compare,Distance> *t ) const;

		// Find the sequentially next or previous element
		//
		AvlNode<T,Compare,Distance> * prev( const T & x) const;
		AvlNode<T,Compare,Distance> * next( const T & x) const;

		// Basic operations
		//
		bool insert( const T & x, AvlNode<T,Compare,Distance> * & t );
		void makeEmpty( AvlNode<T,Compare,Distance> * & t ) const;
		void printTree( ostream& out, AvlNode<T,Compare,Distance> *t, int numTabs = 0, char lr = '_' ) const;

		// Merging two branches
		//
		bool merge( AvlNode<T,Compare,Distance>* b, AvlNode<T,Compare,Distance>* &t);

		// Find methods
		//
		AvlNode<T,Compare,Distance> * findMin( AvlNode<T,Compare,Distance> *t ) const;
		AvlNode<T,Compare,Distance> * findMax( AvlNode<T,Compare,Distance> *t ) const;
		AvlNode<T,Compare,Distance> * find( const T & x, AvlNode<T,Compare,Distance> *t ) const;
		AvlNode<T,Compare,Distance> * findClosest( const T & x, AvlNode<T,Compare,Distance> *t ) const;

		AvlNode<T,Compare,Distance> * prev( AvlNode<T,Compare,Distance>* t) const;
		AvlNode<T,Compare,Distance> * next( AvlNode<T,Compare,Distance>* t) const;

		AvlNode<T,Compare,Distance> * clone( const AvlNode<T,Compare,Distance> *t ) const;

		int height( AvlNode<T,Compare,Distance> *t ) const;

		// A small maximum utility function used for height calculations
		//
		int max( int lhs, int rhs ) const;

		// Tree manipulations
		//
		void rotateWithLeftChild( AvlNode<T,Compare,Distance> * & k2 ) const;
		void rotateWithRightChild( AvlNode<T,Compare,Distance> * & k1 ) const;
		void doubleWithLeftChild( AvlNode<T,Compare,Distance> * & k3 ) const;
		void doubleWithRightChild( AvlNode<T,Compare,Distance> * & k1 ) const;

		// Removes a node and returns true if the node was on the left
		// side of its parent
		//
		void removeNode( AvlNode<T,Compare,Distance>* &node);

		// Perform a sanity check on the tree to make sure the structure is sound
		//
		bool sanityCheck(AvlNode<T,Compare,Distance>* const &node) const;

		// Swap one node with another node, connecting parent references as needed
		//
		void replaceNode(AvlNode<T,Compare,Distance>* &node1, AvlNode<T,Compare,Distance>* &node2);

		// Balances the tree starting at the root node
		//
		void balanceTree() { balanceTree( root ); }
		void balanceTree(AvlNode<T,Compare,Distance>* &node);

		// Returns all elements from a given branch in order
		//
		void getAllElements(vector<T*>& elements, AvlNode<T,Compare,Distance>* root, bool copy) const;

		// Returns all ancestors of a given element
		//
		void getAllAncestors(vector<T*>& ancestors, AvlNode<T,Compare,Distance>* node, bool copy) const;

		// Returns a range query for all of the elements that lie within the min
		// and max inclusive
		//
		void rangeQuery(vector<T*>& range, AvlNode<T,Compare,Distance>* root, const T& min, const T& max, bool copy) const;

		// Range query that calls a callback method on each match
		//
		void rangeQuery(RangeQueryCallback, AvlNode<T,Compare,Distance>* root, const T& min, const T& max, void* arg) const;

		// Same range query but returns the results in a tree
		//
		//void rangeQuery(AvlTree<T,Compare,Distance>& range, AvlNode<T,Compare,Distance>* root, const T& min, const T& max) const;

		// Whether two elements are equal
		//
		bool eq(const T& a, const T&b) const
		{
			return !(_compare(a, b)) && !(_compare(b, a));
		}

		// Whether an element is smaller than another
		//
		bool lt(const T& a, const T&b) const
		{
			return _compare(a, b);
		}

		// Whether an element is smaller than or equal
		//
		bool le(const T& a, const T& b) const
		{
			return lt(a,b) || eq(a,b);
		}

		// Whether an element is greater than another
		//
		bool gt(const T& a, const T& b) const
		{
			return ge(a,b) && !eq(a,b);
		}

		// Whether an element is greater than or equal
		//
		bool ge(const T& a, const T& b) const
		{
			return !(_compare(a, b));
		}

		// Whether to perform sanity checks or not
		//
		bool _sanity;

		// An instance of the functor for comparison
		//
		Compare _compare;

		// An instance of the functor for distance
		//
		Distance _distance;
};



#endif
