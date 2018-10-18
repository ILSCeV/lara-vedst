<div class="card p-0">
    <div class="card-header">
        <h4 class="card-title p-3">
            {{ trans('mainLang.infoFor') }}
        </h4>
    </div>

   <ul class="nav nav-tabs">
       @foreach($clubInfos as $title => $info)
            <li class="{{Lara\Section::current()->title === $title? 'active': ''}} statisticClubPicker nav-item">
                <a aria-expanded="{{Lara\Section::current()->title == $title? 'true' : 'false'}}"
                   href="#{{ str_replace(' ', '-', mb_strtolower($title)) }}"
                   data-toggle="tab" class="nav-link">
                    {{$title}}
                </a>
            </li>
        @endforeach
    </ul>
</div>

<div class="card card-body p-0">
    <div id="memberStatisticsTabs" class="tab-content">
        @foreach($clubInfos as $title => $clubInfo)
            <div class="tab-pane fade in {{ Lara\Section::current()->title === $title ? 'active' : '' }}"
                 id="{{ str_replace(' ', '-', mb_strtolower($title)) }}">
                <table data-toggle="table">
                    <thead>
                        <tr>
                            <th data-field="name" data-sortable="true">
                                {{trans('mainLang.name')}}
                            </th>
                            <th data-field="shifts" data-sortable="true">
                                {{trans('mainLang.totalShifts')}}
                            </th>
                            <th class="col">
                                &nbsp;
                            </td>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach($clubInfo as $info)
                            @php
                                $user = $info->user->user;
                            @endphp
                            <tr class="{{Auth::user()->id === $user->id? 'my-shift' : ''}}">
                                <td>
                                    @include('partials.personStatusMarker', ['status' => $user->status, 'section' => $user->section])
                                    <a href="#" onclick="chosenPerson = '{{$user->name}}'" name="show-stats-person{{$info->user->id}}" id="{{$info->user->id}}" data-toggle="tooltip" data-placement="top" title="{{ $user->fullName() }}">
                                            {{$user->name}}
                                    </a>
                                </td>
                                <td>
                                    @include('partials.statistics.amountOfShiftsDisplay')
                                </td>
                                <td>
                                    @include('partials.statistics.graphicShifts')
                                </td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
        @endforeach
    </div>
</div>
