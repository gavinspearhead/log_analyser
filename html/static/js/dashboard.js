"use strict";

var colours = [
    '#A2383B', '#c78200', '#2f6473', '#38A29F', '#277171', '#A23888', '#71275F','#A28D38',  '#F9F871',
    '#FFC258', '#F38E56', '#A93D62', '#D6605D', '#364C6A', '#2F4858', '#4D4D78', '#8E4375', '#6D4A7C',
    ];

var g_name= '';
var g_type = '';
var g_search = '';
var max_datapoints = 120;

function set_ip_click_handler() {
    $(".ip_addr").unbind("click");
    $(".ip_addr").click(function(event) {
        window.open('https://dnschecker.org/ip-whois-lookup.php?query=' + encodeURIComponent($(this).text()));
//        console.log('http://www.whois.com/whois/' + encodeURIComponent($(this).text()));
        console.log($(this).text());

    });
    }

var simple_types = [
    "ssh_users",
    "ssh_ips",
    "apache_response",
    "apache_ips",
];


function handle_request(name, type, search)
{
    console.log(name, type, search)
    g_name = name;
    g_type = type;
    g_search = search;
    var period = 'today';
    if ($("#daily").is(":checked")) {period = 'today';}
    else if ($("#hourly").is(":checked")) {period = 'hour';}
    else if ($("#yesterday").is(":checked")) {period = 'yesterday';}
    else if ($("#weekly").is(":checked")) {period = 'week';}
    else if ($("#monthly").is(":checked")) {period = 'month';}
    console.log(period);
    $.ajax({
        url: script_root + '/data/',
        type: 'POST',
        data:  JSON.stringify({'name': name, "type": type, 'period': period, 'search': search}),
        cache: false,
        contentType: "application/json;charset=UTF-8",

    }).done(function(data) {
        var res = JSON.parse(data);
        $('#itemstable').html(res.rhtml);
        document.title = ("Log Analyser - " + type + " " + name +  " " + period).replace("_", " ");
        $("#header").text((type + ": " + name).replace("_", " "));
        set_ip_click_handler();
    });
    return false;
}


function set_log_handlers()
{
    $("[id^='ssh_']").unbind('click');
    $("[id^='apache_']").unbind('click');
    $("[id^='ssh_']").click(function(event) {
        var type = "ssh";
        var name = $(this).attr("id").replace('ssh_', '');
        handle_request(name, type)
    });
    $("[id^='apache_']").click(function(event) {
        var type = "apache";
        var name = $(this).attr("id").replace('apache_', '');
        handle_request(name, type)
    });
    $("[name^='timeperiod").click(function(event) {
       handle_request(g_name, g_type, g_search);
    });
    $("#searchbutton").click(function(event) {
        handle_request(g_name, g_type, $("#searchbar").val())
    });
}


function load_graph(canvas_id, type, name, period)
{
//    var x= get_period();
//    var period = x[0];
//    var interval = x[1];
//    var period = "today";
//    var name= "users";
//    var type = "ssh";

    $.ajax({
        url: script_root + '/data/',
        type: 'POST',
        data:  JSON.stringify({'type': type, 'period': period, 'name': name, 'raw': true} ),
        cache: false,
        contentType: "application/json;charset=UTF-8",
    }).done(function(data) {
        var res = JSON.parse(data);
        console.log (res);
//        var interval_size = calculate_yaxis(res.data) ;

        var options= {
            graphTitle: res.title,
            graphTitleFontSize: 16,
            canvasBorders: true,
            canvasBordersWidth: 1,
            barDatasetSpacing: 0,
            barValueSpacing:0,
            animation : false,
            responsive: true,
            legend: true,
            highLight: true,
            annotateLabel: "<%=v2+': '+v1+' '+v3%>",
            annotateDisplay: true,
            yAxisMinimumInterval:1,
            scaleStartValue : 0,

            showXLabels: true,
            showYAxisMin: true,
//            yAxisUnit: res.unit,
            yAxisUnitFontSize: 16,
        };
        if (res.labels.length == 0 || res.data.length == 0) { return }
        var data_sets = [];
        for (var i = 0 ; i < res.data.length; i++) {
            data_sets.push(
            {
                fillColor: colours[i],
                strokeColor: colours[i],
                data: res.data[i],
                title: res.labels[i]
            }
            )
        }

        var data = {
           labels: res.fields,
           datasets: data_sets
//            datasets: [{
//                fillColor: colours[0],
//                strokeColor: colours[0],
//                data: res.data,
//                title: type
//            }]
        }
        console.log(data);
         new Chart(document.getElementById(canvas_id).getContext("2d")).StackedBar(data, options);
    });
    return false;
}

function load_all_graphs()
{
    var types = simple_types;
    var period = 'today';
    if ($("#daily").is(":checked")) {period = 'today';}
    else if ($("#hourly").is(":checked")) {period = 'hour';}
    else if ($("#yesterday").is(":checked")) {period = 'yesterday';}
    else if ($("#weekly").is(":checked")) {period = 'week';}
    else if ($("#monthly").is(":checked")) {period = 'month';}
    $("canvas").each(function() {
        load_graph($(this).attr('id'), $(this).attr("data-type"), $(this).attr("data-name"), period);

    })
    for (let i = 0; i < types.length; i++) {
    }
}

$( document ).ready(function() {
       
//    add_items_lock = 0
    $('body').css('background-image', 'url("' + script_root + '/static/img/background.gif")');
    $('body').css('background-size', 'contain');

    $("[name^='timeperiod").click(function(event) {
       load_all_graphs()
    });
    $('#itemstablediv').scrollTop(0);
    load_all_graphs();

});
