function formatDate(date) {
    const formattedDate = date.substring(0,10) + ' ' + date.substring(11,19);
    return formattedDate
}

export default formatDate; 