
plot_element = ['plot1', 'plot2', 'plot3', 'plot4'];
plot_title = ['title1', 'title2', 'title3', 'title4'];


var ws = new WebSocket('ws://localhost:8000');

var x = 1;

var plot_key = {}

ws.addEventListener('open', function (event) {
	console.log('Connected to the WS Server!')
});

// Connection closed
ws.addEventListener('close', function (event) {
	console.log('Disconnected from the WS Server!')
});




ws.onopen = function () {
	setupPlot();
	console.log('Sending mesg to server')
	ws.send("Message from client");
};


ws.onmessage = function (event) {


	//values_str = (event.data).split(',');
	data = JSON.parse(event.data)

	pps = []
	mbps = []
	len = []


	for (var key of Object.keys(data)) {
		var  info = data[key]['info']
		update_plot_key(key);
		plot_name = plot_key[key]['plot'];
		title_name = plot_key[key]['title'];
		if (info['protocol'] == 'UDP'){
			pps_val = data[key]['data']['pps'];
			jit_val = data[key]['data']['jitter'];
			media = data[key]['data']['media'];
			state = data[key]['data']['state'];
			loss_val = data[key]['data']['loss'];
			len_val =  data[key]['data']['len'];
			mbps_val = data[key]['data']['mbps'];

			pps.push([pps_val]);
			mbps.push([mbps_val]);
			len.push([len_val]);

			document.getElementById(title_name).innerHTML = `${key} --> Destination: ${info['dstport']} ,${media} : ${state} `;
			//Plotly.extendTraces(plot_name, {x: [[x], [x], [x]], y: [[pps_val], [mbps_val], [len_val]]}, [0, 1, 2], 100);
		}
	}


	console.log(pps);
	console.log(mbps);
	console.log(len);
	Plotly.extendTraces('plot1', {x: [[x], [x], [x]], y: pps}, [0, 1, 2], 100);
	Plotly.extendTraces('plot2', {x: [[x], [x], [x]], y: len}, [0, 1, 2], 100);
	Plotly.extendTraces('plot3', {x: [[x], [x], [x]], y: mbps}, [0, 1, 2], 100);

	x++;
}


function update_plot_key(key){
	if (!(key in plot_key)){
		plot_key[key] = {
			'plot': plot_element[key],
			'title': plot_title[key],
		}
	}
	//console.log(plot_key);

}

function setupPlot(){
	
	for (var i = 0; i < 4; i++) {
		var layout = {
			title: plot_element[i],
			font: {
				family: 'Courier New, monospace',
				size: 24
			  },
			showlegend: true,

		};

		var trace1 = {
			x: [0],
			y: [0],
			name: 'Port1',
		}

		var trace2 = {
			x: [0],
			y: [0],
			name: 'Port2',
		}

		var trace3 = {
			x: [0],
			y: [0],
			name: 'Port3',
		}

		var data = [trace1, trace2, trace3]
		Plotly.newPlot(plot_element[i], data, layout);

	}
};
 
