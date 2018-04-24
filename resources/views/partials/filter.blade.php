<div id="section-filter" class="hidden-print">
	{{-- Show/hide events belonging to a chosen section --}}
	@foreach($sections as $section)
		<span id="label-{!! $section["title"] !!}" class="label label-filters palette-{{$section->color}}-500-Primary bg">{!! $section["title"] !!}</span>
	@endforeach
	<span id="label-survey" class="label label-filters palette-Purple-900-Primary bg">{{trans('mainLang.survey')}}</span>
	<select id="section-filter-selector" class="hidden show-tick" multiple title="{{ trans('mainLang.chooseAtLeastOne') }}" data-selected-text-format="count > 2" data-actions-box="true">
	@foreach($sections as $section)
		<option value="filter-{!! $section["title"] !!}" class="palette-{{$section->color}}-500-Primary bg option-shadow">{!! $section["title"] !!}</option>
	@endforeach
		<option value="filter-survey" class="palette-Purple-900-Primary bg option-shadow">{{trans('mainLang.survey')}}</option>
	</select>
</div>

