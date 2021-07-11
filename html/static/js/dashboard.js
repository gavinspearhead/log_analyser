"use strict";

var colours = [
'#A2383B', '#c78200', '#2f6473', '#38A29F', '#277171', '#A23888', '#71275F','#A28D38',  '#F9F871',
    '#FFC258', '#F38E56', '#A93D62', '#D6605D', '#364C6A', '#2F4858', '#4D4D78', '#8E4375', '#6D4A7C',
    ];

var g_name= '';
var g_type = '';
var g_search = '';
var max_datapoints = 120;

var simple_types = [
    "ssh_users",
    "ssh_ips",
    "apache_response",
    "apache_ips",
];



function fmtChartJSPerso(n, p)
{
    if (p.length > 12) {
        var s =p;
        var l =p.length;
        return s.slice(0,5) + "..." + s.slice(l-5, l);
    }
    return p;
}

function load_graph(canvas_id, type, name, period)
{
    $.ajax({
        url: script_root + '/data/',
        type: 'POST',
        data:  JSON.stringify({'type': type, 'period': period, 'name': name, 'raw': true} ),
        cache: false,
        contentType: "application/json;charset=UTF-8",
    }).done(function(data) {
        var res = JSON.parse(data);
        console.log (res);

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
            xScaleLabelsMinimumWidth: 10,
            fmtXLabel: "fn",
            annotateLabel: "<%=v2+': '+v1+' '+v3%>",
            annotateDisplay: true,
            yAxisMinimumInterval:1,
            forceGraphMin : 0,
            graphMin:0,
            scaleSteps : 1,
            scaleStepWidth : 1,
            yAxisUnitFontSize: 16,
        };
        if (res.labels.length == 0 || res.data.length == 0) { return }
        var data_sets = [];
        for (var i = 0 ; i < res.data.length; i++) {
            data_sets.push( {
                fillColor: colours[i % colours.length],
                strokeColor: colours[i % colours.length],
                data: res.data[i],
                title: res.labels[i]
            })
        }

        var data = {
           labels: res.fields,
           datasets: data_sets
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
