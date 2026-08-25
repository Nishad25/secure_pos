import React from "react";
import { useNavigate } from "react-router-dom";
import { getAvatarName, getBgColor } from "../../utils"
import { useDispatch, useSelector } from "react-redux";
import { updateTable } from "../../redux/slices/customerSlice";
import { FaLongArrowAltRight } from "react-icons/fa";
import { enqueueSnackbar } from "notistack";

const TableCard = ({id, name, status, initials, seats}) => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const customerData = useSelector((state) => state.customer);
  const handleClick = (name) => {
    if(status === "Booked") return;

    if(!customerData.customerName?.trim() || !customerData.customerPhone?.trim()){
      enqueueSnackbar("Start an order with the + button on Home first, so we have the customer's name and phone.", { variant: "warning" });
      navigate("/");
      return;
    }

    const table = { tableId: id, tableNo: name }
    dispatch(updateTable({table}))
    navigate(`/menu`);
  };

  return (
    <div onClick={() => handleClick(name)} key={id} className="w-[300px] hover:bg-[#2c2c2c] bg-[#262626] p-4 rounded-lg cursor-pointer">
      <div className="flex items-center justify-between px-1">
        <h1 className="text-[#f5f5f5] text-xl font-semibold">Table <FaLongArrowAltRight className="text-[#ababab] ml-2 inline" /> {name}</h1>
        <p className={`${status === "Booked" ? "text-green-600 bg-[#2e4a40]" : "bg-[#664a04] text-white"} px-2 py-1 rounded-lg`}>
          {status}
        </p>
      </div>
      <div className="flex items-center justify-center mt-5 mb-8">
        <h1 className={`text-white rounded-full p-5 text-xl`} style={{backgroundColor : initials ? getBgColor() : "#1f1f1f"}} >{getAvatarName(initials) || "N/A"}</h1>
      </div>
      <p className="text-[#ababab] text-xs">Seats: <span className="text-[#f5f5f5]">{seats}</span></p>
    </div>
  );
};

export default TableCard;
