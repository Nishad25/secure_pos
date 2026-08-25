import React, { useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { getTotalPrice } from "../../redux/slices/cartSlice";
import { addOrder, payWithCard, updateTable } from "../../https/index";
import { enqueueSnackbar } from "notistack";
import { useMutation } from "@tanstack/react-query";
import { removeAllItems } from "../../redux/slices/cartSlice";
import { removeCustomer } from "../../redux/slices/customerSlice";
import Invoice from "../invoice/Invoice";
import CardPaymentModal from "./CardPaymentModal";

const Bill = () => {
  const dispatch = useDispatch();

  const customerData = useSelector((state) => state.customer);
  const cartData = useSelector((state) => state.cart);
  const total = useSelector(getTotalPrice);
  const taxRate = 5.25;
  const tax = (total * taxRate) / 100;
  const totalPriceWithTax = total + tax;

  const [paymentMethod, setPaymentMethod] = useState();
  const [showInvoice, setShowInvoice] = useState(false);
  const [showCardModal, setShowCardModal] = useState(false);
  const [orderInfo, setOrderInfo] = useState();

  const buildOrderData = (paymentData) => ({
    customerDetails: {
      name: customerData.customerName,
      phone: customerData.customerPhone,
      guests: customerData.guests,
    },
    orderStatus: "In Progress",
    bills: {
      total: total,
      tax: tax,
      totalWithTax: totalPriceWithTax,
    },
    items: cartData,
    table: customerData.table.tableId,
    paymentMethod: paymentMethod,
    ...(paymentData && { paymentData }),
  });

  const handlePlaceOrder = () => {
    if (!customerData.customerName?.trim() || !customerData.customerPhone?.trim()) {
      enqueueSnackbar(
        "Customer details are missing. Go back to Home and start the order with the + button first.",
        { variant: "warning", autoHideDuration: 8000 }
      );
      return;
    }

    if (!paymentMethod) {
      enqueueSnackbar("Please select a payment method!", {
        variant: "warning",
      });

      return;
    }

    if (paymentMethod === "Online") {
      setShowCardModal(true);
      return;
    }

    // Cash payment: place the order directly
    orderMutation.mutate(buildOrderData());
  };

  const cardPaymentMutation = useMutation({
    mutationFn: (cardData) =>
      payWithCard({ ...cardData, amount: totalPriceWithTax.toFixed(2) }),
    onSuccess: (resData) => {
      const { transactionId } = resData.data.data;
      enqueueSnackbar("Payment successful!", { variant: "success" });
      setShowCardModal(false);
      orderMutation.mutate(buildOrderData({ transactionId }));
    },
    onError: (error) => {
      console.log(error);
      enqueueSnackbar(
        error?.response?.data?.message || "Payment failed!",
        { variant: "error" }
      );
    },
  });

  const handleCardPaymentSubmit = (cardData) => {
    cardPaymentMutation.mutate(cardData);
  };

  const orderMutation = useMutation({
    mutationFn: (reqData) => addOrder(reqData),
    onSuccess: (resData) => {
      const { data } = resData.data;
      console.log(data);

      setOrderInfo(data);

      // Update Table
      const tableData = {
        status: "Booked",
        orderId: data._id,
        tableId: data.table,
      };

      setTimeout(() => {
        tableUpdateMutation.mutate(tableData);
      }, 1500);

      enqueueSnackbar("Order Placed!", {
        variant: "success",
      });
      setShowInvoice(true);
    },
    onError: (error) => {
      console.log(error);
      const reason = error?.response?.data?.message || "Unknown error";
      enqueueSnackbar(
        paymentMethod === "Online"
          ? `Payment was received but the order could not be saved (${reason}). Please note the amount and contact support.`
          : `Order could not be saved: ${reason}`,
        { variant: "error", autoHideDuration: 10000 }
      );
    },
  });

  const tableUpdateMutation = useMutation({
    mutationFn: (reqData) => updateTable(reqData),
    onSuccess: (resData) => {
      console.log(resData);
      dispatch(removeCustomer());
      dispatch(removeAllItems());
    },
    onError: (error) => {
      console.log(error);
      enqueueSnackbar("Order was saved but the table status could not be updated.", {
        variant: "warning",
      });
    },
  });

  return (
    <>
      <div className="flex items-center justify-between px-5 mt-2">
        <p className="text-xs text-[#ababab] font-medium mt-2">
          Items({cartData.length})
        </p>
        <h1 className="text-[#f5f5f5] text-md font-bold">
          ₹{total.toFixed(2)}
        </h1>
      </div>
      <div className="flex items-center justify-between px-5 mt-2">
        <p className="text-xs text-[#ababab] font-medium mt-2">Tax(5.25%)</p>
        <h1 className="text-[#f5f5f5] text-md font-bold">₹{tax.toFixed(2)}</h1>
      </div>
      <div className="flex items-center justify-between px-5 mt-2">
        <p className="text-xs text-[#ababab] font-medium mt-2">
          Total With Tax
        </p>
        <h1 className="text-[#f5f5f5] text-md font-bold">
          ₹{totalPriceWithTax.toFixed(2)}
        </h1>
      </div>
      <div className="flex items-center gap-3 px-5 mt-4">
        <button
          onClick={() => setPaymentMethod("Cash")}
          className={`bg-[#1f1f1f] px-4 py-3 w-full rounded-lg text-[#ababab] font-semibold ${
            paymentMethod === "Cash" ? "bg-[#383737]" : ""
          }`}
        >
          Cash
        </button>
        <button
          onClick={() => setPaymentMethod("Online")}
          className={`bg-[#1f1f1f] px-4 py-3 w-full rounded-lg text-[#ababab] font-semibold ${
            paymentMethod === "Online" ? "bg-[#383737]" : ""
          }`}
        >
          Online
        </button>
      </div>

      <div className="flex items-center gap-3 px-5 mt-4">
        <button className="bg-[#025cca] px-4 py-3 w-full rounded-lg text-[#f5f5f5] font-semibold text-lg">
          Print Receipt
        </button>
        <button
          onClick={handlePlaceOrder}
          className="bg-[#f6b100] px-4 py-3 w-full rounded-lg text-[#1f1f1f] font-semibold text-lg"
        >
          Place Order
        </button>
      </div>

      {showInvoice && (
        <Invoice orderInfo={orderInfo} setShowInvoice={setShowInvoice} />
      )}

      <CardPaymentModal
        isOpen={showCardModal}
        onClose={() => setShowCardModal(false)}
        onSubmit={handleCardPaymentSubmit}
        amount={totalPriceWithTax.toFixed(2)}
        isProcessing={cardPaymentMutation.isPending}
      />
    </>
  );
};

export default Bill;
