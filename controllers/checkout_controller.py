from flask import session, render_template, request, redirect, url_for, flash ,jsonify
from models.product import Product
from models.user import User
from models import db

def keranjang():
    if 'cart' not in session:
        session['cart'] = []  # Initialize an empty cart

    cart = session['cart']
    products = []

    # Retrieve product details from the database
    for item in cart:
        product = Product.query.get(item['product_id'])
        if product:
            user = User.query.get(product.user_id)
            store_name = user.name if user else 'Tidak Diketahui'
            product_details = {
                'id': product.id,
                'name': product.nama_barang,
                'price': product.harga,
                'quantity': item['quantity'],
                'image': product.gambar,
                'store_name': store_name, 
                'stock': product.stok,
                'total_price': product.harga * item['quantity']  # Ensure correct calculation
            }
            products.append(product_details)

    # Calculate the subtotal for selected items
    subtotal = sum(item['total_price'] for item in products)

    return render_template('frontend/keranjang.html', products=products, subtotal=subtotal)



def add_to_cart(product_id):
    # Get product from the database
    product = Product.query.get_or_404(product_id)

    # Initialize the cart if it doesn't exist
    if 'cart' not in session:
        session['cart'] = []

    cart = session['cart']

    # Check if the product is already in the cart
    for item in cart:
        if item['product_id'] == product_id:
            # Check stock and update quantity
            if item['quantity'] < product.stok:
                item['quantity'] += 1
                flash(f'{product.nama_barang} has been updated in your cart.', 'success')
            else:
                flash(f'Stock limit reached for {product.nama_barang}.', 'danger')
            session.modified = True
            return redirect(url_for('keranjang'))

    # Add new product to the cart
    cart.append({'product_id': product_id, 'quantity': 1})
    session['cart'] = cart  # Save the updated cart to the session
    flash(f'{product.nama_barang} added to cart.', 'success')
    return redirect(url_for('keranjang'))

def update_cart():

    data = request.get_json()
    product_id = int(data['product_id'])
    new_quantity = int(data['quantity'])

    if 'cart' not in session:
        return jsonify({'error': 'Cart not found'}), 400

    cart = session['cart']
    subtotal = 0

    for item in cart:
        if item['product_id'] == product_id:
            product = Product.query.get(product_id)
            if product and new_quantity <= product.stok:  # Ensure stock limits are respected
                item['quantity'] = new_quantity
                item['total_price'] = new_quantity * product.harga

    session['cart'] = cart  # Save updated cart back to session

    # Return updated total price for the product
    return jsonify({
        'total_price': new_quantity * product.harga
    })