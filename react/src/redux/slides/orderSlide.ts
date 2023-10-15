import { createSlice } from '@reduxjs/toolkit'
import type { PayloadAction } from '@reduxjs/toolkit'
import { Order } from '../../model/OrderModal'
import { AddressShipping } from '../../model/UserModal'
import { clothesOrder } from '../../model/ClothesModal'
import { calculatePriceFinal } from '../../utils/utils'

const initialState: Order = {
    orderItems : [],
    paymentMethod : '',
    isPayment : false,
    addressShip : {} as AddressShipping,
    // addressShip : {
    //     fullName : '',
    //     phone : '',
    //     province : '',
    //     district : '',
    //     ward : '',
    //     addressDetail : '',
    //     type : '',
    //     default : false
    // },
    totalPrice : 0,
    totalQuantity : 0,
    username : ''
}

export const orderSlice = createSlice({
  name: 'order',
  initialState,
  reducers: {
    addProductToOrder : (state , action : PayloadAction<clothesOrder> ) => {
        const orderItem = action.payload;
        const itemPriceFinal = calculatePriceFinal(orderItem.price , orderItem.discount)
        const orderClothes = state.orderItems.find(
            item => item.id === orderItem.id 
            && item.classifyClothes.color === orderItem.classifyClothes.color
            && item.classifyClothes.quantities.size === orderItem.classifyClothes.quantities.size
        );
        if(orderClothes){
            orderClothes.amountBuy += orderItem.amountBuy
        }else{
            state.orderItems.push(orderItem)
        }
        state.totalPrice = state.totalPrice + itemPriceFinal * orderItem.amountBuy;
        state.totalQuantity = state.totalQuantity + orderItem.amountBuy;
        // state.totalPrice = 3000;
        // state.totalQuantity = 4;
    },
    changeAmount : (state , action : PayloadAction<{amountChange : number , orderItem : clothesOrder}>) => {
        const {orderItem , amountChange} = action.payload;
        const orderClothes = state.orderItems.find(
            item => item.id === orderItem.id 
            && item.classifyClothes.color === orderItem.classifyClothes.color
            && item.classifyClothes.quantities.size === orderItem.classifyClothes.quantities.size
        );
        if(orderClothes) {
            orderClothes.amountBuy = amountChange;
            state.totalQuantity = state.orderItems.reduce((total, item) => {
                return total + item.amountBuy;
            }, 0);
            state.totalPrice = state.orderItems.reduce((total, item) => {
                const itemPriceFinal = calculatePriceFinal(item.price, item.discount);
                return total + itemPriceFinal * item.amountBuy;
            }, 0);
        }
    },
    removeProduct : (state , action : PayloadAction<clothesOrder>) => {
        const orderItem = action.payload;
        const orderItemsFilter = state.orderItems.filter(
            item => item.id !== orderItem.id 
            || item.classifyClothes.color !== orderItem.classifyClothes.color
            || item.classifyClothes.quantities.size !== orderItem.classifyClothes.quantities.size
        );
        state.orderItems = [...orderItemsFilter];
        const itemPriceFinal = calculatePriceFinal(orderItem.price , orderItem.discount);
        // state.totalPrice = 0;
        // state.totalQuantity = 0;
        state.totalQuantity -= orderItem.amountBuy;
        state.totalPrice -= (itemPriceFinal * orderItem.amountBuy);
    },
    cloneOrder : (state , action : PayloadAction<Order>) => {
        Object.assign(state, action.payload);
    },
    resetOrder : (state ) => {
        Object.assign(state, initialState);
    },
  },
})

// Action creators are generated for each case reducer function
export const { addProductToOrder , changeAmount ,removeProduct ,cloneOrder , resetOrder } = orderSlice.actions

export default orderSlice.reducer